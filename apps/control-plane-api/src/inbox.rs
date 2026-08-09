//! Durable per-command **delivery** state: has the targeted agent retrieved
//! this command yet?
//!
//! This is a different dimension from the outbox's fanout completion, and both
//! have to be tracked. The outbox answers "did this command reach the
//! queryable trace"; it marks a row complete and stops returning it, so it can
//! never answer "did the agent it targets know about it". A command can be
//! fanned out to the trace *and* still be pending delivery to its agent, and
//! before this module existed the second question had no answer anywhere --
//! which is exactly the gap that let `delivered: true` be read as "the agent
//! stopped".
//!
//! # Delivery semantics
//!
//! **At-least-once, idempotent consumers.** This project already decided that
//! for the whole event pipeline and this does not get to be the exception.
//! Concretely:
//!
//! - A poll returns the commands pending for the calling agent and durably
//!   records a delivery attempt for each *before* the response is written.
//! - A delivered command is suppressed for [`DeliveryPolicy::redelivery_after`]
//!   and then becomes visible again. So a response lost in flight -- or an
//!   agent that crashed between receiving a `stop` and acting on it -- sees the
//!   command again on a later poll rather than losing it. Enactment must
//!   therefore be idempotent, which for `stop` it trivially is: stopping an
//!   already-stopped loop is a no-op, not an error.
//! - Redelivery is bounded by [`DeliveryPolicy::max_attempts`]. A command whose
//!   target never comes back settles instead of being redelivered forever. The
//!   durable audit record of the command itself is the outbox row and the
//!   `control` event in the trace; settling here only stops delivery attempts.
//!
//! Deliberately **not** exactly-once. There is no protocol in which a server
//! can know a unary response was observed by the client, and inventing one
//! here would mean either dropping commands (ack before send) or a second
//! mutating RPC on a channel whose whole design goal is to stay cheap and
//! reachable while everything else is degraded.
//!
//! # Concurrency
//!
//! Every operation runs under one mutex ([`ControlInboxBackend`]), so two
//! concurrent polls -- a restarted agent racing its own predecessor, or a
//! duplicated process -- serialise. The second poll observes the first's
//! delivery record and is inside the redelivery window, so a command is handed
//! to at most one of them. That is asserted by
//! `concurrent_polls_never_hand_one_command_to_two_callers`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::errors::{CommandError, CommandErrorCode};

#[cfg(feature = "postgres")]
#[path = "inbox_postgres.rs"]
mod postgres;

#[cfg(feature = "postgres")]
pub use postgres::PostgresCommandInbox;

/// Suppression window after a delivery attempt before a command becomes
/// visible again.
///
/// **Flagged for the owner as a tunable this pass chose conservatively.** Too
/// short and a slow agent gets the same `stop` repeatedly while it is already
/// acting on it (harmless, since enactment is idempotent, but noisy). Too long
/// and a crashed agent's replacement waits that long to learn it should stop.
/// 30 seconds is short enough that a restarted agent is told to stop well
/// inside any plausible human incident-response loop, and long enough that a
/// 1-2 second poll cadence does not re-serve the same command dozens of times.
pub const DEFAULT_REDELIVERY_AFTER: Duration = Duration::from_secs(30);

/// How many times one command is delivered before it settles.
///
/// At the default window that is roughly four minutes of redelivery. Bounded
/// because an agent that never returns must not leave the gateway serving the
/// same `stop` to nobody forever.
pub const DEFAULT_MAX_DELIVERY_ATTEMPTS: u32 = 8;

/// Default and ceiling for how many commands one poll returns. The ceiling
/// bounds the work and the response size a single caller can ask for; the
/// default is what an unspecified `max_commands` resolves to.
pub const DEFAULT_MAX_COMMANDS_PER_POLL: usize = 16;
pub const MAX_COMMANDS_PER_POLL: usize = 64;

/// Ceiling on tracked commands, mirroring the outbox's own capacity bound.
pub const DEFAULT_INBOX_CAPACITY: usize = 1_000_000;

const MAX_INBOX_RECORD_BYTES: usize = 512 * 1024;
const MAX_INBOX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// One command awaiting (or having received) delivery to its target agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommand {
    pub command_id: String,
    pub workspace_id: String,
    pub namespace_id: String,
    pub agent_id: String,
    pub run_id: String,
    pub trace_id: String,
    /// Lowercase action name, exactly as it appears in the emitted `control`
    /// event's `data.action` -- `stop`, `pause`, `resume`, `inject`,
    /// `set_budget`.
    pub action: String,
    pub reason_code: Option<String>,
    /// The operator-submitted `parameters` object, prost-encoded. Stored as
    /// opaque bytes rather than re-parsed: this module never interprets
    /// command content, and `inject.content` in particular is explicitly
    /// untrusted data that must reach the runtime byte-identical to what was
    /// recorded.
    #[serde(default)]
    pub parameters: Vec<u8>,
    /// RFC 3339 UTC timestamp, the same value stamped on the `control` event.
    pub issued_at: String,
    /// 1 on first delivery. Zero in a stored record that has never been
    /// delivered; the value returned to a caller is always at least 1.
    #[serde(default)]
    pub delivery_attempt: u32,
}

/// Identifies one stored command.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InboxKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub command_id: String,
}

/// The server-derived target of a poll.
///
/// `agent_id` comes only from an authenticated caller's *bound* agent identity
/// -- never from a request field. That is the whole isolation property, and it
/// is why this type has no constructor taking a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollTarget {
    pub agent_id: String,
    pub limit: usize,
}

/// Decides whether the authenticated caller holds a given workspace/namespace.
///
/// The inbox deliberately does not know how scope is granted; it asks. The
/// only implementation on the serving path wraps the authenticated
/// `apex_event_ingest::Caller` and defers to its own `allows_scope`, so the
/// answer comes from the credential and nothing else.
pub trait ScopeAuthorizer {
    fn allows(&self, workspace_id: &str, namespace_id: &str) -> bool;
}

/// A single explicitly-allowed scope. Test and embedding helper; the serving
/// path uses the authenticated caller instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactScope {
    pub workspace_id: String,
    pub namespace_id: String,
}

impl ScopeAuthorizer for ExactScope {
    fn allows(&self, workspace_id: &str, namespace_id: &str) -> bool {
        self.workspace_id == workspace_id && self.namespace_id == namespace_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryPolicy {
    pub redelivery_after: Duration,
    pub max_attempts: u32,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            redelivery_after: DEFAULT_REDELIVERY_AFTER,
            max_attempts: DEFAULT_MAX_DELIVERY_ATTEMPTS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    Recorded,
    /// The same `command_id` was already recorded. Idempotent: an operator
    /// resubmitting a command must not queue a second delivery of it.
    AlreadyRecorded,
}

/// Durable delivery-state store.
pub trait CommandInbox: Send {
    /// Idempotently records a command as awaiting delivery to its agent.
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError>;

    /// Returns the commands currently deliverable to `target` within the
    /// scopes `scopes` authorizes, marking a delivery attempt on each.
    /// `now_millis` is passed in rather than read here so the window
    /// arithmetic is testable without sleeping.
    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError>;

    /// Count of commands that have never been delivered. Diagnostics and
    /// tests only; never exposed on the wire.
    fn undelivered_count(&mut self) -> usize;
}

impl<T: CommandInbox + ?Sized> CommandInbox for Box<T> {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        (**self).record(command)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        (**self).claim(target, scopes, policy, now_millis)
    }

    fn undelivered_count(&mut self) -> usize {
        (**self).undelivered_count()
    }
}

/// In-memory delivery state, shared by both backends.
///
/// `FileCommandInbox` is this plus a journal: every mutation is appended and
/// fsynced before the in-memory state changes, and startup replays the journal
/// into it. Keeping the decision logic in one place means the file backend
/// cannot drift from the in-memory one on the question that matters -- which
/// commands a given caller is entitled to see.
#[derive(Debug, Default)]
struct InboxState {
    /// Insertion order, so a poll returns oldest-first without sorting.
    order: Vec<InboxKey>,
    entries: HashMap<InboxKey, Entry>,
    capacity: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    command: PendingCommand,
    attempts: u32,
    last_delivered_millis: Option<u64>,
}

impl InboxState {
    fn new(capacity: usize) -> Self {
        Self {
            order: Vec::new(),
            entries: HashMap::new(),
            capacity,
        }
    }

    fn key(command: &PendingCommand) -> InboxKey {
        InboxKey {
            workspace_id: command.workspace_id.clone(),
            namespace_id: command.namespace_id.clone(),
            command_id: command.command_id.clone(),
        }
    }

    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        let key = Self::key(command);
        if self.entries.contains_key(&key) {
            return Ok(RecordResult::AlreadyRecorded);
        }
        if self.entries.len() >= self.capacity {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        self.order.push(key.clone());
        self.entries.insert(
            key,
            Entry {
                command: command.clone(),
                attempts: 0,
                last_delivered_millis: None,
            },
        );
        Ok(RecordResult::Recorded)
    }

    /// Applies a replayed delivery record. Never widens state: an unknown key
    /// is ignored rather than synthesised, so a truncated or reordered journal
    /// cannot invent a command.
    fn apply_delivery(&mut self, key: &InboxKey, attempt: u32, at_millis: u64) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.attempts = entry.attempts.max(attempt);
            entry.last_delivered_millis = Some(
                entry
                    .last_delivered_millis
                    .map_or(at_millis, |previous| previous.max(at_millis)),
            );
        }
    }

    /// Which stored commands `target` is entitled to receive right now.
    ///
    /// Every clause here is a server-derived predicate. There is no branch on
    /// anything a caller supplied except `limit`, which can only shorten the
    /// result.
    fn deliverable(
        &self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Vec<InboxKey> {
        let mut selected = Vec::new();
        for key in &self.order {
            if selected.len() >= target.limit {
                break;
            }
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            // Target identity, then scope. Both are answered by the caller's
            // own credential; there is no path by which a request field
            // reaches either comparison.
            if entry.command.agent_id != target.agent_id {
                continue;
            }
            if !scopes.allows(&entry.command.workspace_id, &entry.command.namespace_id) {
                continue;
            }
            if entry.attempts >= policy.max_attempts {
                continue;
            }
            let visible = match entry.last_delivered_millis {
                None => true,
                Some(delivered_at) => {
                    now_millis.saturating_sub(delivered_at)
                        >= policy.redelivery_after.as_millis() as u64
                }
            };
            if visible {
                selected.push(key.clone());
            }
        }
        selected
    }

    fn mark_delivered(&mut self, key: &InboxKey, now_millis: u64) -> Option<PendingCommand> {
        let entry = self.entries.get_mut(key)?;
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_delivered_millis = Some(now_millis);
        let mut command = entry.command.clone();
        command.delivery_attempt = entry.attempts;
        Some(command)
    }

    fn undelivered_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.attempts == 0)
            .count()
    }
}

/// Non-durable inbox for unit tests and embedded use.
#[derive(Debug)]
pub struct InMemoryCommandInbox {
    state: InboxState,
}

impl InMemoryCommandInbox {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: InboxState::new(capacity.max(1)),
        }
    }
}

impl Default for InMemoryCommandInbox {
    fn default() -> Self {
        Self::new(DEFAULT_INBOX_CAPACITY)
    }
}

impl CommandInbox for InMemoryCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        self.state.record(command)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        let keys = self.state.deliverable(target, scopes, policy, now_millis);
        Ok(keys
            .iter()
            .filter_map(|key| self.state.mark_delivered(key, now_millis))
            .collect())
    }

    fn undelivered_count(&mut self) -> usize {
        self.state.undelivered_count()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum InboxRecord {
    Command(PendingCommand),
    Delivered {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        attempt: u32,
        at_millis: u64,
    },
}

/// Append-only, fsync-backed delivery journal.
///
/// Deliberately the same shape and the same disciplines as
/// `apex_event_ingest::FileOutbox`: confined beneath an operator-owned base
/// directory, symlinks refused, bounded record and file sizes, an exclusive
/// writer lock held for the process lifetime, and a startup replay that fails
/// closed on malformed data rather than silently dropping a pending command.
#[derive(Debug)]
pub struct FileCommandInbox {
    file: File,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    state: InboxState,
}

impl FileCommandInbox {
    pub fn open(path: &Path, base: &Path, capacity: usize) -> Result<Self, CommandError> {
        if capacity == 0 || capacity > DEFAULT_INBOX_CAPACITY {
            return Err(configuration_error());
        }
        let canonical_base = base.canonicalize().map_err(|_| configuration_error())?;
        let parent = path.parent().ok_or_else(configuration_error)?;
        let canonical_parent = parent.canonicalize().map_err(|_| configuration_error())?;
        if !canonical_parent.starts_with(&canonical_base)
            || path.file_name().is_none()
            || (path.exists() && path.is_symlink())
        {
            return Err(configuration_error());
        }
        if path.exists() {
            let metadata = fs::metadata(path).map_err(|_| configuration_error())?;
            if !metadata.is_file() || metadata.len() > MAX_INBOX_FILE_BYTES {
                return Err(configuration_error());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|_| configuration_error())?;
        let lock_path = path.with_extension(format!(
            "{}.lock",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("journal")
        ));
        let writer_lock = OpenOptions::new()
            .create(true)
            // The lock file's content is never read; only its exclusive-lock
            // state is meaningful. `truncate(false)` keeps any existing bytes
            // rather than discarding them on reopen -- the same lint fix
            // `FileOutbox` already carries.
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| configuration_error())?;
        fs2::FileExt::try_lock_exclusive(&writer_lock).map_err(|_| configuration_error())?;
        let mut inbox = Self {
            file,
            _writer_lock: writer_lock,
            state: InboxState::new(capacity),
        };
        inbox.load()?;
        Ok(inbox)
    }

    fn load(&mut self) -> Result<(), CommandError> {
        let reader = BufReader::new(self.file.try_clone().map_err(|_| configuration_error())?);
        for line in reader.lines() {
            let line = line.map_err(|_| configuration_error())?;
            if line.len() > MAX_INBOX_RECORD_BYTES {
                return Err(configuration_error());
            }
            let record: InboxRecord =
                serde_json::from_str(&line).map_err(|_| configuration_error())?;
            match record {
                InboxRecord::Command(command) => {
                    // A replayed record is re-validated rather than trusted:
                    // the journal lives on a mounted volume, and a command
                    // whose target identifiers do not satisfy the same grammar
                    // the accept path enforced could otherwise be introduced
                    // by editing a file.
                    if !is_recordable(&command) {
                        return Err(configuration_error());
                    }
                    self.state.record(&command)?;
                }
                InboxRecord::Delivered {
                    workspace_id,
                    namespace_id,
                    command_id,
                    attempt,
                    at_millis,
                } => {
                    self.state.apply_delivery(
                        &InboxKey {
                            workspace_id,
                            namespace_id,
                            command_id,
                        },
                        attempt,
                        at_millis,
                    );
                }
            }
        }
        Ok(())
    }

    fn append(&mut self, record: &InboxRecord) -> Result<(), CommandError> {
        self.append_batch(std::slice::from_ref(record))
    }

    /// Append a group of journal records with one durability barrier.
    ///
    /// A poll claims several commands at once. Fsyncing after every delivery
    /// record made the file backend's latency scale with the poll size even
    /// though the records are one atomic claim from the caller's perspective.
    /// The state is still mutated only after the complete batch is durable.
    fn append_batch(&mut self, records: &[InboxRecord]) -> Result<(), CommandError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut encoded = Vec::new();
        for record in records {
            let mut record_bytes = serde_json::to_vec(record).map_err(|_| CommandError::internal())?;
            record_bytes.push(b'\n');
            if record_bytes.len() > MAX_INBOX_RECORD_BYTES {
                return Err(CommandError::new(
                    CommandErrorCode::Capacity,
                    "The durable command inbox is at capacity. Retry after operator remediation.",
                ));
            }
            encoded.extend_from_slice(&record_bytes);
        }
        let current = self
            .file
            .metadata()
            .map_err(|_| configuration_error())?
            .len();
        if current.saturating_add(encoded.len() as u64) > MAX_INBOX_FILE_BYTES {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        self.file
            .write_all(&encoded)
            .and_then(|_| self.file.sync_data())
            .map_err(|_| CommandError::internal())
    }
}

impl CommandInbox for FileCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        if !is_recordable(command) {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "The command was malformed: check target identifiers, action, and required parameters for the requested action.",
            ));
        }
        let key = InboxState::key(command);
        if self.state.entries.contains_key(&key) {
            return Ok(RecordResult::AlreadyRecorded);
        }
        // Journal first, then mutate memory: a crash between the two leaves a
        // record that replays into the same state, never a delivery the
        // journal cannot account for.
        self.append(&InboxRecord::Command(command.clone()))?;
        self.state.record(command)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        let keys = self.state.deliverable(target, scopes, policy, now_millis);

        let records: Vec<_> = keys
            .iter()
            .map(|key| {
                let attempt = self
                    .state
                    .entries
                    .get(key)
                    .map_or(0, |entry| entry.attempts)
                    .saturating_add(1);
                InboxRecord::Delivered {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    attempt,
                    at_millis: now_millis,
                }
            })
            .collect();

        // Durable *before* any command is handed back. One sync for the poll
        // keeps the same crash semantics while avoiding one fsync per command.
        self.append_batch(&records)?;

        let mut delivered = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(command) = self.state.mark_delivered(&key, now_millis) {
                delivered.push(command);
            }
        }
        Ok(delivered)
    }

    fn undelivered_count(&mut self) -> usize {
        self.state.undelivered_count()
    }
}

fn configuration_error() -> CommandError {
    CommandError::new(
        CommandErrorCode::Internal,
        "The control gateway failed to process the request.",
    )
}

/// The grammar a stored command must satisfy.
///
/// Identical in spirit to the ingest boundary's `is_scope_identifier`: this is
/// the last place a value read back off disk is checked before it is compared
/// against an authenticated caller's identity, and an identifier containing a
/// delimiter or control byte is how such a comparison gets confused.
fn is_recordable(command: &PendingCommand) -> bool {
    is_identifier(&command.workspace_id)
        && is_identifier(&command.namespace_id)
        && is_identifier(&command.agent_id)
        && is_identifier(&command.run_id)
        && is_identifier(&command.trace_id)
        && is_identifier(&command.command_id)
        && matches!(
            command.action.as_str(),
            "stop" | "pause" | "resume" | "inject" | "set_budget"
        )
        && command
            .reason_code
            .as_deref()
            .is_none_or(is_identifier)
        && command.issued_at.len() <= 64
        && command.issued_at.is_ascii()
        && !command.issued_at.chars().any(char::is_control)
        && command.parameters.len() <= MAX_INBOX_RECORD_BYTES / 2
}

/// Stable semantic identity for a delivery record. The attempt counter is
/// deliberately excluded: redelivery mutates that operational field but not
/// the command an agent is meant to enact.
#[cfg(feature = "postgres")]
pub(super) fn command_hash(command: &PendingCommand) -> Result<[u8; 32], CommandError> {
    use sha2::{Digest, Sha256};

    let mut semantic = command.clone();
    semantic.delivery_attempt = 0;
    let encoded = serde_json::to_vec(&semantic).map_err(|_| CommandError::internal())?;
    Ok(Sha256::digest(encoded).into())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Serialises every inbox operation behind one lock, exactly as
/// [`crate::outbox::ControlOutboxBackend`] does for the outbox and for the same
/// reasons: the concurrency argument above depends on it, and a future
/// Postgres-backed implementation would drive its own runtime and block.
pub struct ControlInboxBackend {
    inner: Mutex<Box<dyn CommandInbox + Send>>,
}

impl ControlInboxBackend {
    pub fn new(inbox: Box<dyn CommandInbox + Send>) -> Self {
        Self {
            inner: Mutex::new(inbox),
        }
    }

    pub fn with_lock<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn CommandInbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        let mut guard = self.inner.lock().map_err(|_| CommandError::internal())?;
        Ok(f(&mut guard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(command_id: &str, agent_id: &str) -> PendingCommand {
        PendingCommand {
            command_id: command_id.to_owned(),
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: agent_id.to_owned(),
            run_id: "run-1".to_owned(),
            trace_id: "trace-1".to_owned(),
            action: "stop".to_owned(),
            reason_code: Some("operator.request".to_owned()),
            parameters: Vec::new(),
            issued_at: "2026-08-08T00:00:00.000000Z".to_owned(),
            delivery_attempt: 0,
        }
    }

    fn target(agent_id: &str) -> PollTarget {
        PollTarget {
            agent_id: agent_id.to_owned(),
            limit: DEFAULT_MAX_COMMANDS_PER_POLL,
        }
    }

    fn scope(workspace_id: &str, namespace_id: &str) -> ExactScope {
        ExactScope {
            workspace_id: workspace_id.to_owned(),
            namespace_id: namespace_id.to_owned(),
        }
    }

    fn acme_prod() -> ExactScope {
        scope("acme", "prod")
    }

    #[test]
    fn a_recorded_command_is_delivered_once_then_suppressed_for_the_window() {
        let mut inbox = InMemoryCommandInbox::new(16);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let policy = DeliveryPolicy::default();

        let first = inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].command_id, "cmd-1");
        assert_eq!(first[0].delivery_attempt, 1);

        // Inside the window: suppressed.
        let second = inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1_500)
            .unwrap();
        assert!(second.is_empty());

        // Past the window: visible again, because a response that never
        // arrived must not silently lose an operator's stop.
        let third = inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1_000 + 30_000)
            .unwrap();
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].delivery_attempt, 2);
    }

    /// The isolation claim, at the storage layer. Agent B's poll must not see
    /// agent A's command even though both are in the same workspace and
    /// namespace and the store holds both.
    #[test]
    fn a_command_is_never_delivered_to_another_agent() {
        let mut inbox = InMemoryCommandInbox::new(16);
        inbox.record(&command("cmd-a", "agent-a")).unwrap();
        inbox.record(&command("cmd-b", "agent-b")).unwrap();
        let policy = DeliveryPolicy::default();

        let for_b = inbox
            .claim(&target("agent-b"), &acme_prod(), policy, 1_000)
            .unwrap();
        assert_eq!(for_b.len(), 1);
        assert_eq!(for_b[0].command_id, "cmd-b");

        let for_a = inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
            .unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].command_id, "cmd-a");
    }

    #[test]
    fn a_command_is_never_delivered_across_a_workspace_or_namespace_boundary() {
        let mut inbox = InMemoryCommandInbox::new(16);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let policy = DeliveryPolicy::default();
        for (workspace, namespace) in [("other", "prod"), ("acme", "staging"), ("other", "staging")]
        {
            let claimed = inbox
                .claim(
                    &target("agent-a"),
                    &scope(workspace, namespace),
                    policy,
                    1_000,
                )
                .unwrap();
            assert!(
                claimed.is_empty(),
                "a credential scoped to {workspace}/{namespace} must not receive acme/prod's command"
            );
        }
    }

    #[test]
    fn recording_the_same_command_twice_is_idempotent() {
        let mut inbox = InMemoryCommandInbox::new(16);
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::Recorded
        );
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::AlreadyRecorded
        );
        let claimed = inbox
            .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 1)
            .unwrap();
        assert_eq!(claimed.len(), 1, "a resubmitted command must not queue twice");
    }

    #[test]
    fn redelivery_is_bounded_by_the_attempt_ceiling() {
        let mut inbox = InMemoryCommandInbox::new(16);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let policy = DeliveryPolicy {
            redelivery_after: Duration::from_secs(1),
            max_attempts: 3,
        };
        let mut delivered = 0;
        for tick in 0..10u64 {
            delivered += inbox
                .claim(&target("agent-a"), &acme_prod(), policy, tick * 5_000)
                .unwrap()
                .len();
        }
        assert_eq!(
            delivered, 3,
            "a command whose target never returns must stop being redelivered"
        );
    }

    #[test]
    fn the_limit_only_ever_narrows_a_result_set() {
        let mut inbox = InMemoryCommandInbox::new(16);
        for index in 0..5 {
            inbox
                .record(&command(&format!("cmd-{index}"), "agent-a"))
                .unwrap();
        }
        let mut narrow = target("agent-a");
        narrow.limit = 2;
        let claimed = inbox
            .claim(&narrow, &acme_prod(), DeliveryPolicy::default(), 1_000)
            .unwrap();
        assert_eq!(claimed.len(), 2);
        // Oldest first, so a poll cannot starve the earliest command.
        assert_eq!(claimed[0].command_id, "cmd-0");
        assert_eq!(claimed[1].command_id, "cmd-1");
    }

    #[test]
    fn capacity_is_refused_rather_than_silently_dropping_a_command() {
        let mut inbox = InMemoryCommandInbox::new(1);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::Capacity);
    }

    /// A restarted or duplicated agent process polling concurrently must not
    /// both receive the same command. The backend's single mutex is what makes
    /// that true, so this drives it through the backend rather than the raw
    /// inbox.
    #[test]
    fn concurrent_polls_never_hand_one_command_to_two_callers() {
        use std::sync::Arc;

        let backend = Arc::new(ControlInboxBackend::new(Box::new(
            InMemoryCommandInbox::new(64),
        )));
        backend
            .with_lock(|inbox| inbox.record(&command("cmd-1", "agent-a")))
            .unwrap()
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let backend = Arc::clone(&backend);
            handles.push(std::thread::spawn(move || {
                backend
                    .with_lock(|inbox| {
                        inbox.claim(
                            &target("agent-a"),
                            &acme_prod(),
                            DeliveryPolicy::default(),
                            5_000,
                        )
                    })
                    .unwrap()
                    .unwrap()
                    .len()
            }));
        }
        let total: usize = handles.into_iter().map(|handle| handle.join().unwrap()).sum();
        assert_eq!(
            total, 1,
            "exactly one concurrent poll may receive the command"
        );
    }

    #[test]
    fn file_inbox_survives_a_restart_with_its_delivery_state_intact() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64).unwrap();
            inbox.record(&command("cmd-1", "agent-a")).unwrap();
            inbox.record(&command("cmd-2", "agent-a")).unwrap();
            let claimed = inbox
                .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 10_000)
                .unwrap();
            assert_eq!(claimed.len(), 2);
        }
        {
            // Reopened: both commands are known and both are inside the
            // redelivery window, so a restarted gateway does not immediately
            // re-serve a command the agent already has.
            let mut inbox = FileCommandInbox::open(&path, &dir, 64).unwrap();
            assert_eq!(inbox.undelivered_count(), 0);
            assert!(
                inbox
                    .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 12_000)
                    .unwrap()
                    .is_empty()
            );
            // ... and past the window they come back, attempt count preserved.
            let again = inbox
                .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 41_000)
                .unwrap();
            assert_eq!(again.len(), 2);
            assert!(again.iter().all(|command| command.delivery_attempt == 2));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_refuses_a_path_outside_its_base() {
        let dir = std::env::temp_dir().join(format!("apex-inbox-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join("apex-inbox-escape.jsonl");
        assert!(FileCommandInbox::open(&outside, &dir, 64).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_command_with_an_out_of_grammar_identifier_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-grammar-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut inbox = FileCommandInbox::open(&dir.join("inbox.jsonl"), &dir, 64).unwrap();
        let mut bad = command("cmd-1", "agent a");
        bad.action = "stop".to_owned();
        assert!(inbox.record(&bad).is_err());
        let mut bad_action = command("cmd-2", "agent-a");
        bad_action.action = "self_destruct".to_owned();
        assert!(inbox.record(&bad_action).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
