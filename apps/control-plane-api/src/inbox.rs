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
//!
//! The Postgres backend does not have that mutex -- it uses a bounded pool of
//! independent connections instead, on purpose, so concurrent gateway work
//! gets row-level locking rather than one process-wide lock. `record`'s
//! per-scope capacity check therefore takes a scoped `pg_advisory_xact_lock`
//! of its own to close a count-then-insert TOCTOU window under READ
//! COMMITTED; see the comment on [`PostgresCommandInbox::record`] and
//! `postgres_inbox_scope_quota_holds_under_concurrent_writers_to_one_scope`.
//!
//! # Capacity
//!
//! Two independent ceilings, both enforced on every `record`:
//!
//! - [`DEFAULT_INBOX_CAPACITY`] -- one number shared by every tenant.
//! - [`DEFAULT_INBOX_SCOPE_QUOTA`] -- a per-`(workspace_id, namespace_id)`
//!   ceiling enforced in *addition* to the global one, so a single scoped
//!   credential cannot fill the entire shared inbox and block delivery --
//!   including an emergency `stop` -- to every other tenant. This is the
//!   actual multi-tenant fairness boundary; see
//!   `a_scope_at_its_quota_never_blocks_a_different_scope_from_recording` for
//!   the regression test.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::errors::{CommandError, CommandErrorCode};

#[cfg(feature = "postgres")]
#[path = "inbox_postgres.rs"]
mod postgres;

#[cfg(feature = "postgres")]
pub use postgres::PostgresCommandInbox;

#[cfg(feature = "postgres")]
pub use postgres::RecoveringPostgresCommandInbox;

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

/// Default and ceiling for how many command summaries one `ListCommands`
/// page returns. Same discipline as `DEFAULT_MAX_COMMANDS_PER_POLL` /
/// `MAX_COMMANDS_PER_POLL`: a hard maximum a caller cannot raise by asking
/// for more, and a sane default when `page_size` is left unspecified. An
/// operator dashboard scanning a scope mid-incident is still one caller
/// asking the gateway to do bounded work and return a bounded response --
/// unbounded pagination would mean an unbounded query and an unbounded
/// response on the one channel ADR-0006 needs to stay reachable when
/// everything else is degraded.
pub const DEFAULT_LIST_COMMANDS_PAGE_SIZE: usize = 50;
pub const MAX_LIST_COMMANDS_PAGE_SIZE: usize = 200;

/// Ceiling on tracked commands, mirroring the outbox's own capacity bound.
pub const DEFAULT_INBOX_CAPACITY: usize = 1_000_000;

/// Default and validation ceiling for
/// `APEX_CONTROL_INBOX_MAX_COMMANDS_PER_SCOPE`: the most tracked commands one
/// `(workspace_id, namespace_id)` scope may occupy, enforced in *addition* to
/// [`DEFAULT_INBOX_CAPACITY`].
///
/// [`DEFAULT_INBOX_CAPACITY`] is one number shared by every tenant. An
/// operator credential is commonly scoped to a single workspace/namespace
/// (`OperatorCaller::scoped` in `auth.rs`; every Keycloak-issued credential
/// maps IdP claims down to the same narrow scopes in `keycloak.rs`), but
/// nothing stopped a single scoped credential from filling the *entire*
/// shared inbox by itself -- a compromised credential, a buggy automation, or
/// just an unlucky burst from one tenant could leave zero room for every
/// other tenant's commands, including an emergency `stop`, until an operator
/// intervened. There was no per-workspace/per-agent quota. This constant is
/// that quota, and it is the actual security boundary being protected here,
/// not the global ceiling: it bounds what any one scope may occupy so a
/// single tenant's burst cannot starve delivery to everyone else, regardless
/// of how far the global ceiling is from being hit.
///
/// **20,000**, chosen in the low tens of thousands deliberately: no
/// legitimate single tenant should ever need anywhere near the 1,000,000
/// global ceiling in flight at once, and 20,000 is two orders of magnitude
/// below it -- a single compromised or malfunctioning scope can consume at
/// most 2% of the shared inbox before every other tenant is still guaranteed
/// room for theirs. It is also generous relative to the front door: at the
/// default admission ceiling (`APEX_CONTROL_ADMISSION_LIMIT`, 50 commands per
/// operator per second), a single credential sustaining the maximum admitted
/// rate continuously would still take roughly 6-7 minutes to exhaust its own
/// quota -- comfortably longer than any legitimate burst, comfortably
/// shorter than leaving a runaway credential to run for hours.
pub const DEFAULT_INBOX_SCOPE_QUOTA: usize = 20_000;

const MAX_INBOX_RECORD_BYTES: usize = 512 * 1024;
const MAX_INBOX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const INBOX_COMPACTION_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;
const INBOX_COMPACTION_DELIVERY_RECORDS: usize = 1_024;

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
    /// `set_budget`, `resolve_hold`.
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

/// One command summary returned by `ListCommands` -- exactly the fields
/// `GetCommandStatus` and `PendingControlCommand` already expose for a
/// command's identity and delivery state, and nothing else: no `parameters`,
/// no `run_id`/`trace_id`. An operator who needs those already has the
/// `command_id` this carries and can pull the full record from the
/// queryable trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSummary {
    pub command_id: String,
    pub agent_id: String,
    pub action: String,
    pub state: DeliveryStatus,
    pub delivery_attempt: u32,
    pub issued_at: String,
    /// This entry's position in the backend's total order, oldest first.
    /// `service.rs` never interprets it -- it round-trips it as the opaque
    /// `next_page_token` string -- but it is what makes resuming a scan
    /// stable: a caller passes back the last summary's `sequence` and the
    /// next page resumes strictly after it, so a command recorded,
    /// delivered, or settled by someone else while this caller pages
    /// through a large scope can never shift already-returned rows the way
    /// an offset would.
    pub sequence: u64,
}

/// Enumeration parameters for `ListCommands`, scoped to a single
/// workspace/namespace the caller has already been authorized against by
/// the same `operator.allows_scope` check `GetCommandStatus` uses.
///
/// Unlike `PollTarget`, there is no `ScopeAuthorizer` here: the scope is not
/// a set the backend re-checks per row, it is the one scope the caller
/// already proved before this query was built -- exactly as
/// `GetCommandStatus`'s `InboxKey` already carries an unchecked
/// `workspace_id`/`namespace_id` pair for the same reason.
#[derive(Debug, Clone, Copy)]
pub struct ListCommandsQuery<'a> {
    pub workspace_id: &'a str,
    pub namespace_id: &'a str,
    /// Narrows to one agent's commands. `None` returns every agent's
    /// commands in scope.
    pub agent_id: Option<&'a str>,
    /// Narrows to one delivery state. `None` returns commands in every
    /// state.
    pub state: Option<DeliveryStatus>,
    /// Resume strictly after this sequence. `0` starts from the beginning --
    /// valid because every backend assigns sequences starting at 1.
    pub after_sequence: u64,
    /// Already clamped into `[1, MAX_LIST_COMMANDS_PAGE_SIZE]` by the caller
    /// (`service.rs`); the inbox trusts it rather than re-clamping, so the
    /// ceiling is enforced in exactly one place.
    pub limit: usize,
    pub max_attempts: u32,
}

/// One page of [`CommandSummary`] results.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListCommandsPage {
    pub commands: Vec<CommandSummary>,
    /// `true` when at least one more command past this page's last entry
    /// matches the query. The caller resumes with the last summary's
    /// `sequence` as the next `after_sequence`.
    pub has_more: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckResult {
    Acknowledged,
    AlreadyAcknowledged,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelResult {
    Cancelled,
    /// The same command was already cancelled by an earlier call. Idempotent,
    /// for the same reason `AckResult::AlreadyAcknowledged` is: an operator
    /// retrying a cancellation after a lost response must not get an error.
    AlreadyCancelled,
    /// No stored command matches this key -- never issued, or its identity
    /// has already been retired past the idempotency window.
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Acknowledged,
    Exhausted,
    /// An operator cancelled this command via `CancelCommand` before it was
    /// ever delivered. Terminal and durable, the same as `Acknowledged`.
    Cancelled,
}

/// The one rule every backend applies to turn attempts/acknowledgement into
/// a [`DeliveryStatus`]. Used by `status` and `list` below, and by
/// `PostgresCommandInbox`'s own `status` and `list_commands`. Kept in one
/// place so "what does DELIVERED mean" cannot drift between backends, or
/// between the two RPCs (`GetCommandStatus`, `ListCommands`) that report it.
pub(super) fn resolve_delivery_status(
    cancelled: bool,
    acknowledged: bool,
    attempts: u32,
    max_attempts: u32,
) -> DeliveryStatus {
    if cancelled {
        // `cancel` only ever succeeds while `attempts == 0`, so this is
        // checked first: an entry that is both `cancelled` and, by that
        // invariant, still at zero attempts must never resolve to `Pending`.
        DeliveryStatus::Cancelled
    } else if acknowledged {
        DeliveryStatus::Acknowledged
    } else if attempts == 0 {
        DeliveryStatus::Pending
    } else if attempts >= max_attempts {
        DeliveryStatus::Exhausted
    } else {
        DeliveryStatus::Delivered
    }
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

    /// Count of active delivery records, including records already delivered
    /// but retained for redelivery or idempotency.
    fn pending_count(&mut self) -> usize;

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError>;

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError>;

    /// Enumerates commands in a scope for operator visibility -- "what is
    /// currently pending here" -- without requiring the caller to already
    /// know a `command_id`. Cursor-paginated: see
    /// [`ListCommandsQuery::after_sequence`]. Implementations must apply a
    /// stable, oldest-first order so a caller resuming with a previous
    /// page's cursor sees the next commands, never a repeat or a gap.
    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError>;

    /// Retracts a command that has never been delivered.
    ///
    /// Operator-initiated, unlike `acknowledge` -- there is deliberately no
    /// `PollTarget`/agent-identity check here, the same as `status` above.
    /// The caller's authority is scope, checked by the caller against `key`'s
    /// `workspace_id`/`namespace_id` before this is ever reached; the inbox
    /// itself only needs the exact key.
    ///
    /// Succeeds only while the command's delivery attempt count is still
    /// zero. A command delivered even once is refused with
    /// `CommandErrorCode::AlreadyDelivered` rather than cancelled: the agent
    /// may already be acting on it, and cancelling it out from under a
    /// delivery would recreate exactly the "did the agent get it or not"
    /// ambiguity this module exists to eliminate.
    fn cancel(&mut self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError>;

    /// Retires settled delivery state after the configured idempotency window.
    /// Implementations must preserve the command identity until that window
    /// expires, so a retry cannot create a second delivery of the same command.
    fn maintain(
        &mut self,
        _now_millis: u64,
        _retention_millis: u64,
        _max_attempts: u32,
    ) -> Result<(), CommandError> {
        Ok(())
    }
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

    fn pending_count(&mut self) -> usize {
        (**self).pending_count()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        (**self).acknowledge(target, key, delivery_attempt, now_millis)
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        (**self).status(key, max_attempts)
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        (**self).list_commands(query)
    }

    fn cancel(&mut self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError> {
        (**self).cancel(key, now_millis)
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        (**self).maintain(now_millis, retention_millis, max_attempts)
    }
}

/// In-memory delivery state, shared by both backends.
///
/// `FileCommandInbox` is this plus a journal: every mutation is appended and
/// fsynced before the in-memory state changes, and startup replays the journal
/// into it. Keeping the decision logic in one place means the file backend
/// cannot drift from the in-memory one on the question that matters -- which
/// commands a given caller is entitled to see.
#[derive(Debug, Clone, Default)]
struct InboxState {
    /// Insertion order, so a poll returns oldest-first without sorting.
    order: Vec<InboxKey>,
    entries: HashMap<InboxKey, Entry>,
    /// Settled command identities retained for the idempotency window.
    retired: HashMap<InboxKey, u64>,
    capacity: usize,
    /// Per-`(workspace_id, namespace_id)` ceiling, enforced in *addition* to
    /// `capacity`. See [`DEFAULT_INBOX_SCOPE_QUOTA`] for why this exists.
    scope_quota: usize,
    /// Live per-scope count of tracked commands -- `entries` plus `retired`,
    /// the same two buckets `capacity` counts globally -- kept incrementally
    /// so enforcing `scope_quota` in `record` never has to scan the whole
    /// inbox.
    scope_counts: HashMap<(String, String), usize>,
    /// Monotonically increasing identity assigned to each command at
    /// `record` time, purely for `list`'s cursor pagination. Never reused --
    /// not even when a retired command's key is later reused, since a fresh
    /// `record` always draws the next value -- so a page token issued before
    /// a retirement can never be confused with a later, unrelated command.
    /// This is the in-memory/file counterpart to `PostgresCommandInbox`'s
    /// `sequence` column (`BIGSERIAL`), which starts at 1 for the same
    /// reason this starts at 1: `0` is left free to mean "from the start".
    next_sequence: u64,
}

#[derive(Debug, Clone)]
struct Entry {
    command: PendingCommand,
    attempts: u32,
    last_delivered_millis: Option<u64>,
    acknowledged: bool,
    sequence: u64,
    /// Set by `cancel`. Mutually exclusive with `acknowledged` by
    /// construction: cancellation only ever succeeds while `attempts == 0`,
    /// and `acknowledge` requires `attempts >= 1`.
    cancelled: bool,
}

impl InboxState {
    fn new(capacity: usize, scope_quota: usize) -> Self {
        Self {
            order: Vec::new(),
            entries: HashMap::new(),
            retired: HashMap::new(),
            capacity,
            scope_quota,
            scope_counts: HashMap::new(),
            next_sequence: 1,
        }
    }

    fn key(command: &PendingCommand) -> InboxKey {
        InboxKey {
            workspace_id: command.workspace_id.clone(),
            namespace_id: command.namespace_id.clone(),
            command_id: command.command_id.clone(),
        }
    }

    fn scope(command: &PendingCommand) -> (String, String) {
        (command.workspace_id.clone(), command.namespace_id.clone())
    }

    /// Checks whether `command` may be recorded, without mutating any state.
    ///
    /// `Ok(Some(result))` means there is nothing left to do -- `command` is
    /// already present, so recording it is a no-op. `Ok(None)` means `command`
    /// is new and passed every admission check, so [`Self::insert_recorded`]
    /// is guaranteed to succeed. `Err` means it was refused.
    ///
    /// Split out from the insert step specifically so a caller with a durable
    /// journal (`FileCommandInbox`) can run this check *before* writing to
    /// that journal. A rejected command must never reach the journal: replay
    /// re-runs this same check against a `Command` journal entry via
    /// `load()`, and because that check depends on how full the scope already
    /// is, a phantom entry for a command that was refused for capacity would
    /// very likely still be over-quota at replay time -- and since `load()`
    /// deliberately fails closed on an admission failure rather than silently
    /// dropping it (the same rule this crate applies to every malformed
    /// credential-table entry), a single rejected write could otherwise make
    /// the journal permanently unreplayable until an operator hand-edited the
    /// file. Checking first is what keeps a rejected command out of the
    /// journal in the first place, so replay never has a reason to see one.
    fn check_recordable(
        &self,
        command: &PendingCommand,
    ) -> Result<Option<RecordResult>, CommandError> {
        let key = Self::key(command);
        if self.entries.contains_key(&key) || self.retired.contains_key(&key) {
            return Ok(Some(RecordResult::AlreadyRecorded));
        }
        if self.entries.len().saturating_add(self.retired.len()) >= self.capacity {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        let scope = Self::scope(command);
        // Enforced in *addition* to the global ceiling above. This is what
        // stops one workspace/namespace from filling the entire shared inbox
        // and blocking delivery -- including an emergency `stop` -- to every
        // other tenant. See [`DEFAULT_INBOX_SCOPE_QUOTA`].
        if self.scope_counts.get(&scope).copied().unwrap_or(0) >= self.scope_quota {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "This workspace/namespace has reached its share of the durable command inbox. Retry after operator remediation.",
            ));
        }
        Ok(None)
    }

    /// Unconditionally inserts a command that [`Self::check_recordable`] has
    /// already admitted. Never call this without having just checked --
    /// nothing here re-validates capacity, scope quota, or duplication.
    fn insert_recorded(&mut self, command: &PendingCommand) {
        let key = Self::key(command);
        let scope = Self::scope(command);
        // A tombstone that has just expired may still have its old key in the
        // insertion-order vector. Remove it before reusing the identity so a
        // later compaction cannot emit the command twice.
        self.order.retain(|existing| existing != &key);
        self.order.push(key.clone());
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.entries.insert(
            key,
            Entry {
                command: command.clone(),
                attempts: 0,
                last_delivered_millis: None,
                acknowledged: false,
                sequence,
                cancelled: false,
            },
        );
        *self.scope_counts.entry(scope).or_insert(0) += 1;
    }

    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        if let Some(result) = self.check_recordable(command)? {
            return Ok(result);
        }
        self.insert_recorded(command);
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
            if entry.acknowledged {
                continue;
            }
            if entry.cancelled {
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

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
    ) -> AckResult {
        let Some(entry) = self.entries.get_mut(key) else {
            return AckResult::NotFound;
        };
        if entry.command.agent_id != target.agent_id
            || delivery_attempt == 0
            || delivery_attempt > entry.attempts
        {
            return AckResult::NotFound;
        }
        if entry.acknowledged {
            return AckResult::AlreadyAcknowledged;
        }
        entry.acknowledged = true;
        AckResult::Acknowledged
    }

    /// Retracts a never-delivered command. See `CommandInbox::cancel` for the
    /// full contract.
    fn cancel(&mut self, key: &InboxKey) -> Result<CancelResult, CommandError> {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.cancelled {
                return Ok(CancelResult::AlreadyCancelled);
            }
            if entry.attempts > 0 {
                return Err(CommandError::already_delivered());
            }
            entry.cancelled = true;
            return Ok(CancelResult::Cancelled);
        }
        if self.retired.contains_key(key) {
            // `retire` (called only from `maintain`) only ever tombstones an
            // entry that was `acknowledged` or hit the attempt ceiling --
            // both imply at least one delivery -- so a key found here was
            // necessarily delivered before its state was cleaned up.
            return Err(CommandError::already_delivered());
        }
        Ok(CancelResult::NotFound)
    }

    fn status(&self, key: &InboxKey, max_attempts: u32) -> Option<(DeliveryStatus, u32)> {
        let entry = self.entries.get(key)?;
        let status = resolve_delivery_status(
            entry.cancelled,
            entry.acknowledged,
            entry.attempts,
            max_attempts,
        );
        Some((status, entry.attempts))
    }

    /// Enumerates stored commands for `ListCommands`, oldest-first by the
    /// sequence assigned at `record` time -- the same identity `order`
    /// already preserves insertion order by, made explicit here so a caller
    /// can resume after the last-seen entry rather than by a position that
    /// shifts under concurrent inserts and retirements.
    ///
    /// Every clause is a server-derived or caller-narrowing predicate, the
    /// same shape `deliverable` already follows: `workspace_id`/
    /// `namespace_id` come from a scope the caller was already authorized
    /// against before this was called (`service.rs`), and `agent_id`/`state`
    /// can only ever narrow the result further.
    fn list(&self, query: &ListCommandsQuery<'_>) -> (Vec<CommandSummary>, bool) {
        let mut collected = Vec::with_capacity(query.limit.min(64));
        let mut has_more = false;
        for key in &self.order {
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            if entry.sequence <= query.after_sequence {
                continue;
            }
            if entry.command.workspace_id != query.workspace_id
                || entry.command.namespace_id != query.namespace_id
            {
                continue;
            }
            if let Some(agent_id) = query.agent_id
                && entry.command.agent_id != agent_id
            {
                continue;
            }
            let status = resolve_delivery_status(
                entry.cancelled,
                entry.acknowledged,
                entry.attempts,
                query.max_attempts,
            );
            if let Some(filter) = query.state
                && filter != status
            {
                continue;
            }
            if collected.len() >= query.limit {
                has_more = true;
                break;
            }
            collected.push(CommandSummary {
                command_id: entry.command.command_id.clone(),
                agent_id: entry.command.agent_id.clone(),
                action: entry.command.action.clone(),
                state: status,
                delivery_attempt: entry.attempts,
                issued_at: entry.command.issued_at.clone(),
                sequence: entry.sequence,
            });
        }
        (collected, has_more)
    }

    fn retire(&mut self, key: &InboxKey, retired_at_millis: u64) {
        self.entries.remove(key);
        self.retired.insert(key.clone(), retired_at_millis);
    }

    fn remove_expired_retired(&mut self, cutoff_millis: u64) -> bool {
        let before = self.retired.len();
        // Collect first, mutate `scope_counts` after: `retired`'s own borrow
        // inside `retain`'s closure must not overlap a mutable borrow of a
        // different field being updated from within it.
        let mut expired_scopes: Vec<(String, String)> = Vec::new();
        self.retired.retain(|key, retired_at| {
            let expired = *retired_at <= cutoff_millis;
            if expired {
                expired_scopes.push((key.workspace_id.clone(), key.namespace_id.clone()));
            }
            !expired
        });
        // The identity is leaving the inbox entirely here (not merely being
        // retired), so this -- not `retire` -- is where its scope's share is
        // freed back up.
        for scope in expired_scopes {
            if let Some(count) = self.scope_counts.get_mut(&scope) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.scope_counts.remove(&scope);
                }
            }
        }
        before != self.retired.len()
    }
}

/// Non-durable inbox for unit tests and embedded use.
#[derive(Debug)]
pub struct InMemoryCommandInbox {
    state: InboxState,
}

impl InMemoryCommandInbox {
    /// `scope_quota` is the same per-`(workspace_id, namespace_id)` ceiling
    /// `FileCommandInbox` and `PostgresCommandInbox` enforce; both are clamped
    /// to at least 1 rather than rejected outright, matching this type's role
    /// as the permissive test/embedding backend -- strict startup validation
    /// (reject zero, reject over capacity) lives on the durable backends'
    /// `Result`-returning constructors instead.
    pub fn new(capacity: usize, scope_quota: usize) -> Self {
        Self {
            state: InboxState::new(capacity.max(1), scope_quota.max(1)),
        }
    }
}

impl Default for InMemoryCommandInbox {
    fn default() -> Self {
        Self::new(DEFAULT_INBOX_CAPACITY, DEFAULT_INBOX_SCOPE_QUOTA)
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

    fn pending_count(&mut self) -> usize {
        self.state.entries.len()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        _now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        Ok(self.state.acknowledge(target, key, delivery_attempt))
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        Ok(self.state.status(key, max_attempts))
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        let (commands, has_more) = self.state.list(query);
        Ok(ListCommandsPage { commands, has_more })
    }

    fn cancel(&mut self, key: &InboxKey, _now_millis: u64) -> Result<CancelResult, CommandError> {
        self.state.cancel(key)
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
    Acknowledged {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        at_millis: u64,
    },
    Retired {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        retired_at_millis: u64,
    },
    /// Durable record of an operator cancellation. Replayed the same way
    /// `Acknowledged` is: `load()` sets the in-memory flag and discards
    /// `at_millis`, which exists for the journal's own readability rather
    /// than to drive any replay decision -- same as `Acknowledged`'s.
    Cancelled {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
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
    file: Option<File>,
    path: std::path::PathBuf,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    state: InboxState,
    delivery_records_since_compaction: usize,
}

impl FileCommandInbox {
    pub fn open(
        path: &Path,
        base: &Path,
        capacity: usize,
        scope_quota: usize,
    ) -> Result<Self, CommandError> {
        if capacity == 0 || capacity > DEFAULT_INBOX_CAPACITY {
            return Err(configuration_error());
        }
        // Same fail-loud discipline as `capacity` immediately above: a
        // misconfigured per-scope quota (zero, or wider than the global
        // ceiling it is supposed to sit inside of) is a startup error, not a
        // value to silently clamp.
        if scope_quota == 0 || scope_quota > capacity {
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
            file: Some(file),
            path: path.to_owned(),
            _writer_lock: writer_lock,
            state: InboxState::new(capacity, scope_quota),
            delivery_records_since_compaction: 0,
        };
        inbox.load()?;
        Ok(inbox)
    }

    fn load(&mut self) -> Result<(), CommandError> {
        let reader = BufReader::new(
            self.file
                .as_ref()
                .ok_or_else(configuration_error)?
                .try_clone()
                .map_err(|_| configuration_error())?,
        );
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
                InboxRecord::Acknowledged {
                    workspace_id,
                    namespace_id,
                    command_id,
                    ..
                } => {
                    if let Some(entry) = self.state.entries.get_mut(&InboxKey {
                        workspace_id,
                        namespace_id,
                        command_id,
                    }) {
                        entry.acknowledged = true;
                    }
                }
                InboxRecord::Retired {
                    workspace_id,
                    namespace_id,
                    command_id,
                    retired_at_millis,
                } => {
                    self.state.retire(
                        &InboxKey {
                            workspace_id,
                            namespace_id,
                            command_id,
                        },
                        retired_at_millis,
                    );
                }
                InboxRecord::Cancelled {
                    workspace_id,
                    namespace_id,
                    command_id,
                    ..
                } => {
                    if let Some(entry) = self.state.entries.get_mut(&InboxKey {
                        workspace_id,
                        namespace_id,
                        command_id,
                    }) {
                        entry.cancelled = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn append(&mut self, record: &InboxRecord) -> Result<(), CommandError> {
        self.append_batch(std::slice::from_ref(record))
    }

    fn encode_records(records: &[InboxRecord]) -> Result<Vec<u8>, CommandError> {
        let mut encoded = Vec::new();
        for record in records {
            let mut record_bytes =
                serde_json::to_vec(record).map_err(|_| CommandError::internal())?;
            record_bytes.push(b'\n');
            if record_bytes.len() > MAX_INBOX_RECORD_BYTES {
                return Err(CommandError::new(
                    CommandErrorCode::Capacity,
                    "The durable command inbox is at capacity. Retry after operator remediation.",
                ));
            }
            encoded.extend_from_slice(&record_bytes);
        }
        if encoded.len() as u64 > MAX_INBOX_FILE_BYTES {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        Ok(encoded)
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
        let encoded = Self::encode_records(records)?;
        let current = self
            .file
            .as_ref()
            .ok_or_else(configuration_error)?
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
            .as_mut()
            .ok_or_else(configuration_error)?
            .write_all(&encoded)
            .and_then(|_| {
                self.file
                    .as_ref()
                    .ok_or(std::io::Error::other("inbox journal is closed"))?
                    .sync_data()
            })
            .map_err(|_| CommandError::internal())
    }

    fn snapshot_records(&self) -> Vec<InboxRecord> {
        let mut records = Vec::with_capacity(self.state.entries.len() * 2);
        for key in &self.state.order {
            let Some(entry) = self.state.entries.get(key) else {
                continue;
            };
            records.push(InboxRecord::Command(entry.command.clone()));
            if entry.attempts > 0 {
                records.push(InboxRecord::Delivered {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    attempt: entry.attempts,
                    at_millis: entry.last_delivered_millis.unwrap_or_default(),
                });
            }
            if entry.acknowledged {
                records.push(InboxRecord::Acknowledged {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    at_millis: entry.last_delivered_millis.unwrap_or_default(),
                });
            }
            if entry.cancelled {
                // A cancelled entry is always undelivered (`attempts == 0`),
                // so there is no delivery timestamp to carry forward; 0 is
                // consistent with the `Acknowledged` case above, whose
                // `at_millis` is likewise informational only and discarded on
                // replay.
                records.push(InboxRecord::Cancelled {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    at_millis: entry.last_delivered_millis.unwrap_or_default(),
                });
            }
        }
        for (key, retired_at_millis) in &self.state.retired {
            records.push(InboxRecord::Retired {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                retired_at_millis: *retired_at_millis,
            });
        }
        records
    }

    /// Rewrites the journal to one command record plus the latest delivery
    /// record per command. The snapshot is fully durable before the old file
    /// is replaced, and the writer lock remains held throughout the swap.
    fn compact(&mut self) -> Result<(), CommandError> {
        let encoded = Self::encode_records(&self.snapshot_records())?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(configuration_error)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| configuration_error())?
            .as_nanos();
        let temp_path = self.path.with_file_name(format!(
            ".{file_name}.compact-{}-{nonce}",
            std::process::id()
        ));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|_| CommandError::internal())?;
        let result = temp
            .write_all(&encoded)
            .and_then(|_| temp.sync_data())
            .map_err(|_| CommandError::internal());
        if result.is_err() {
            drop(temp);
            let _ = fs::remove_file(&temp_path);
            return result;
        }
        drop(temp);

        // Closing the old handle is required on Windows before rename can
        // replace the journal path. The replacement is already durable, so a
        // failure here can reopen the original and leave it authoritative.
        let old = self.file.take().ok_or_else(configuration_error)?;
        drop(old);
        if let Err(error) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&self.path)
                    .map_err(|_| configuration_error())?,
            );
            let _ = error;
            return Err(CommandError::internal());
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| configuration_error())?,
        );
        self.state
            .order
            .retain(|key| self.state.entries.contains_key(key));
        // Directory fsync is not supported uniformly on Windows; the file
        // snapshot and rename are still durable enough for the next replay.
        self.delivery_records_since_compaction = 0;
        Ok(())
    }

    fn compact_if_needed(&mut self) {
        let Ok(size) = self
            .file
            .as_ref()
            .ok_or_else(configuration_error)
            .and_then(|file| file.metadata().map_err(|_| configuration_error()))
            .map(|metadata| metadata.len())
        else {
            return;
        };
        if size < INBOX_COMPACTION_THRESHOLD_BYTES
            || self.delivery_records_since_compaction < INBOX_COMPACTION_DELIVERY_RECORDS
        {
            return;
        }
        let _ = self.compact();
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
        // Checked before the journal write, not after: a command this inbox
        // is about to refuse (a duplicate, or one over the global/per-scope
        // capacity) must never reach the journal at all. See
        // `InboxState::check_recordable` for why -- a phantom journal entry
        // for a refused command could otherwise poison every future replay.
        let Some(result) = self.state.check_recordable(command)? else {
            // Journal first, then mutate memory: a crash between the two
            // leaves a record that replays into the same state, never a
            // delivery the journal cannot account for. Safe to journal
            // unconditionally from here: `check_recordable` just confirmed
            // `insert_recorded` cannot fail.
            self.append(&InboxRecord::Command(command.clone()))?;
            self.state.insert_recorded(command);
            return Ok(RecordResult::Recorded);
        };
        Ok(result)
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
        self.delivery_records_since_compaction = self
            .delivery_records_since_compaction
            .saturating_add(records.len());
        self.compact_if_needed();
        Ok(delivered)
    }

    fn undelivered_count(&mut self) -> usize {
        self.state.undelivered_count()
    }

    fn pending_count(&mut self) -> usize {
        self.state.entries.len()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        let result = self.state.acknowledge(target, key, delivery_attempt);
        if matches!(result, AckResult::Acknowledged)
            && let Err(error) = self.append(&InboxRecord::Acknowledged {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                at_millis: now_millis,
            })
        {
            if let Some(entry) = self.state.entries.get_mut(key) {
                entry.acknowledged = false;
            }
            return Err(error);
        }
        Ok(result)
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        Ok(self.state.status(key, max_attempts))
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        let (commands, has_more) = self.state.list(query);
        Ok(ListCommandsPage { commands, has_more })
    }

    fn cancel(&mut self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError> {
        let result = self.state.cancel(key)?;
        // Journal after the in-memory mutation, mirroring `acknowledge`: if
        // the append fails, the in-memory flag is rolled back so the two
        // never disagree about whether this command is cancelled.
        if matches!(result, CancelResult::Cancelled)
            && let Err(error) = self.append(&InboxRecord::Cancelled {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                at_millis: now_millis,
            })
        {
            if let Some(entry) = self.state.entries.get_mut(key) {
                entry.cancelled = false;
            }
            return Err(error);
        }
        Ok(result)
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        let cutoff_millis = now_millis.saturating_sub(retention_millis);
        let previous = self.state.clone();
        let settled: Vec<_> = self
            .state
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                ((entry.acknowledged || entry.attempts >= max_attempts)
                    && entry
                        .last_delivered_millis
                        .is_some_and(|delivered_at| delivered_at <= cutoff_millis))
                .then_some(key.clone())
            })
            .collect();
        for key in &settled {
            self.state.retire(key, now_millis);
        }
        let changed = !settled.is_empty() || self.state.remove_expired_retired(cutoff_millis);
        if !changed {
            return Ok(());
        }
        if let Err(error) = self.compact() {
            self.state = previous;
            return Err(error);
        }
        Ok(())
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
            "stop" | "pause" | "resume" | "inject" | "set_budget" | "resolve_hold"
        )
        && command.reason_code.as_deref().is_none_or(is_identifier)
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

/// Serialises file and in-memory inbox operations behind one lock. Postgres
/// uses a bounded set of independent connections so concurrent gateway work
/// can use row-level locking without sharing one process mutex.
pub struct ControlInboxBackend {
    inner: InboxBackendInner,
}

enum InboxBackendInner {
    Single(Mutex<Box<dyn CommandInbox + Send>>),
    Pool {
        connections: Vec<Mutex<Box<dyn CommandInbox + Send>>>,
        next: AtomicUsize,
    },
}

impl ControlInboxBackend {
    pub fn new(inbox: Box<dyn CommandInbox + Send>) -> Self {
        Self {
            inner: InboxBackendInner::Single(Mutex::new(inbox)),
        }
    }

    pub fn new_pool(inboxes: Vec<Box<dyn CommandInbox + Send>>) -> Result<Self, CommandError> {
        if inboxes.is_empty() {
            return Err(CommandError::internal());
        }
        Ok(Self {
            inner: InboxBackendInner::Pool {
                connections: inboxes.into_iter().map(Mutex::new).collect(),
                next: AtomicUsize::new(0),
            },
        })
    }

    pub fn with_lock<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn CommandInbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        match &self.inner {
            InboxBackendInner::Single(inner) => {
                let mut guard = inner.lock().map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
            InboxBackendInner::Pool { connections, next } => {
                let index = next.fetch_add(1, Ordering::Relaxed) % connections.len();
                let mut guard = connections[index]
                    .lock()
                    .map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
        }
    }

    pub fn pending_count(&self) -> Result<u64, CommandError> {
        let count = self.with_lock(|inbox| inbox.pending_count())?;
        u64::try_from(count).map_err(|_| CommandError::internal())
    }

    pub fn undelivered_count(&self) -> Result<u64, CommandError> {
        let count = self.with_lock(|inbox| inbox.undelivered_count())?;
        u64::try_from(count).map_err(|_| CommandError::internal())
    }

    pub fn acknowledge(
        &self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        self.with_lock(|inbox| inbox.acknowledge(target, key, delivery_attempt, now_millis))?
    }

    pub fn status(
        &self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        self.with_lock(|inbox| inbox.status(key, max_attempts))?
    }

    pub fn list_commands(
        &self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        self.with_lock(|inbox| inbox.list_commands(query))?
    }

    pub fn cancel(&self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError> {
        self.with_lock(|inbox| inbox.cancel(key, now_millis))?
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
        let mut inbox = InMemoryCommandInbox::new(16, 16);
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
        let mut inbox = InMemoryCommandInbox::new(16, 16);
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
        let mut inbox = InMemoryCommandInbox::new(16, 16);
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
        let mut inbox = InMemoryCommandInbox::new(16, 16);
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::Recorded
        );
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::AlreadyRecorded
        );
        let claimed = inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                1,
            )
            .unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "a resubmitted command must not queue twice"
        );
    }

    #[test]
    fn redelivery_is_bounded_by_the_attempt_ceiling() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
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
    fn acknowledging_a_delivery_is_idempotent_and_suppresses_redelivery() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
        inbox.record(&command("cmd-ack", "agent-a")).unwrap();
        let policy = DeliveryPolicy {
            redelivery_after: Duration::ZERO,
            max_attempts: 3,
        };
        let delivered = inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1)
            .unwrap();
        assert_eq!(delivered[0].delivery_attempt, 1);
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-ack".to_owned(),
        };
        assert_eq!(
            inbox.acknowledge(&target("agent-a"), &key, 1, 2).unwrap(),
            AckResult::Acknowledged
        );
        assert_eq!(
            inbox.acknowledge(&target("agent-a"), &key, 1, 3).unwrap(),
            AckResult::AlreadyAcknowledged
        );
        assert!(
            inbox
                .claim(&target("agent-a"), &acme_prod(), policy, 4)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            inbox.status(&key, 3).unwrap(),
            Some((DeliveryStatus::Acknowledged, 1))
        );
    }

    #[test]
    fn cancelling_an_undelivered_command_succeeds_and_it_is_never_polled() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
        inbox.record(&command("cmd-cancel", "agent-a")).unwrap();
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-cancel".to_owned(),
        };
        assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::Cancelled);
        // Idempotent: a retried cancellation (lost response, operator
        // double-click) must not error.
        assert_eq!(
            inbox.cancel(&key, 1_500).unwrap(),
            CancelResult::AlreadyCancelled
        );
        assert_eq!(
            inbox.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS).unwrap(),
            Some((DeliveryStatus::Cancelled, 0))
        );
        // The whole point: a cancelled command must never reach a poll.
        assert!(
            inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    2_000
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cancelling_an_already_delivered_command_is_refused() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
        inbox
            .record(&command("cmd-cancel-late", "agent-a"))
            .unwrap();
        let delivered = inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                1_000,
            )
            .unwrap();
        assert_eq!(delivered.len(), 1);
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-cancel-late".to_owned(),
        };
        let error = inbox.cancel(&key, 2_000).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::AlreadyDelivered);
        // Refused, not silently no-op'd: the command must still be exactly
        // as deliverable/acknowledgeable as it was before the refused call.
        assert_eq!(
            inbox.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS).unwrap(),
            Some((DeliveryStatus::Delivered, 1))
        );
    }

    #[test]
    fn cancelling_an_unknown_command_id_is_reported_as_not_found() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-never-issued".to_owned(),
        };
        assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::NotFound);
    }

    #[test]
    fn the_limit_only_ever_narrows_a_result_set() {
        let mut inbox = InMemoryCommandInbox::new(16, 16);
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
        let mut inbox = InMemoryCommandInbox::new(1, 1);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::Capacity);
    }

    /// The actual regression test for the multi-tenant-fairness finding: one
    /// workspace/namespace filling its own per-scope quota must never block a
    /// *different* scope from recording -- including, in production, an
    /// emergency `stop`. The global ceiling (16) is left far from binding so
    /// only the per-scope quota (1) can be responsible for either outcome
    /// below.
    #[test]
    fn a_scope_at_its_quota_never_blocks_a_different_scope_from_recording() {
        let mut inbox = InMemoryCommandInbox::new(16, 1);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
        assert_eq!(
            error.code,
            CommandErrorCode::Capacity,
            "acme/prod must be refused once it is at its own quota"
        );

        let mut other = command("cmd-other", "agent-b");
        other.workspace_id = "other-workspace".to_owned();
        other.namespace_id = "other-ns".to_owned();
        assert_eq!(
            inbox.record(&other).unwrap(),
            RecordResult::Recorded,
            "a scope with room left must not be refused because a different \
             scope exhausted its own quota"
        );
    }

    /// The per-scope ceiling is enforced on its own terms, distinct from the
    /// global capacity: a generous global ceiling (100) does not save a
    /// scope from its own tight quota (2).
    #[test]
    fn the_scope_quota_is_enforced_independently_of_the_global_capacity() {
        let mut inbox = InMemoryCommandInbox::new(100, 2);
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        inbox.record(&command("cmd-2", "agent-a")).unwrap();
        let error = inbox.record(&command("cmd-3", "agent-a")).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::Capacity);
        assert_eq!(
            inbox.pending_count(),
            2,
            "the global inbox is nowhere near its own ceiling; only the scope quota fired"
        );
    }

    /// Settlement frees a scope's share back up: once a command's tombstone
    /// expires past the retention window, the identity leaves the inbox
    /// entirely and the scope is no longer counted against its quota.
    #[test]
    fn expiring_a_retired_command_frees_its_scope_quota() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-scope-quota-retire-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let policy = DeliveryPolicy {
            redelivery_after: Duration::ZERO,
            max_attempts: 1,
        };
        let mut inbox = FileCommandInbox::open(&path, &dir, 16, 1).unwrap();
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        assert_eq!(
            inbox
                .claim(&target("agent-a"), &acme_prod(), policy, 1)
                .unwrap()
                .len(),
            1
        );
        let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::Capacity);

        // Settle and expire the tombstone.
        inbox.maintain(1_000, 100, 1).unwrap();
        inbox.maintain(2_000, 100, 1).unwrap();

        assert_eq!(
            inbox.record(&command("cmd-2", "agent-a")).unwrap(),
            RecordResult::Recorded,
            "once the settled command's identity fully expires, its scope's \
             quota must be freed for a new command"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression test for a command that is *refused* -- for global capacity
    /// or, as exercised here, per-scope quota -- never reaching the journal.
    ///
    /// Before this was fixed, `FileCommandInbox::record` journaled every
    /// command before checking whether it could actually be admitted, so a
    /// rejected command still left a durable `Command` entry behind. Replay
    /// re-runs the same admission check against every journaled `Command`,
    /// and fails closed (propagates the error rather than silently dropping
    /// the entry) on a check that does not pass -- so a single
    /// rejected-for-quota write could poison every future restart: the
    /// gateway would fail to come back up at all until an operator
    /// hand-edited the journal file to remove the phantom line. This test
    /// proves the fix by actually restarting the inbox from disk after a
    /// rejection, which is the exact step that used to be able to fail.
    #[test]
    fn a_command_refused_for_scope_quota_is_never_journaled_and_does_not_poison_replay() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-refused-not-journaled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 1).unwrap();
            assert_eq!(
                inbox.record(&command("cmd-1", "agent-a")).unwrap(),
                RecordResult::Recorded
            );
            let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
            assert_eq!(
                error.code,
                CommandErrorCode::Capacity,
                "the second command must be refused: the scope is already at its quota of 1"
            );
        }
        // The regression: reopening (replaying the journal from a cold start,
        // exactly what a restarted gateway does) must succeed, and must see
        // only the one command that was actually admitted. If `cmd-2` had
        // been journaled despite being refused, replay would hit the same
        // over-quota check on it -- still failing, since nothing freed the
        // scope's one slot in between -- and this `unwrap()` would panic
        // instead of the gateway ever coming back up.
        let mut reopened = FileCommandInbox::open(&path, &dir, 64, 1)
            .expect("a rejected command must never leave a journal entry that fails replay");
        assert_eq!(
            reopened.pending_count(),
            1,
            "only the admitted command should have survived the restart"
        );
        // The scope is still at its quota after restart -- state.record()
        // recomputes quota from what actually replayed, not from anything
        // the rejected write might have left behind -- so a third command in
        // the same scope is refused exactly as it was before the restart.
        let error = reopened.record(&command("cmd-3", "agent-a")).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::Capacity);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_open_rejects_an_invalid_scope_quota() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-scope-quota-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            FileCommandInbox::open(&dir.join("zero.jsonl"), &dir, 64, 0).is_err(),
            "a zero per-scope quota must be refused, not treated as unlimited"
        );
        assert!(
            FileCommandInbox::open(&dir.join("over.jsonl"), &dir, 64, 65).is_err(),
            "a per-scope quota wider than the global capacity must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restarted or duplicated agent process polling concurrently must not
    /// both receive the same command. The backend's single mutex is what makes
    /// that true, so this drives it through the backend rather than the raw
    /// inbox.
    #[test]
    fn concurrent_polls_never_hand_one_command_to_two_callers() {
        use std::sync::Arc;

        let backend = Arc::new(ControlInboxBackend::new(Box::new(
            InMemoryCommandInbox::new(64, 64),
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
        let total: usize = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
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
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            inbox.record(&command("cmd-1", "agent-a")).unwrap();
            inbox.record(&command("cmd-2", "agent-a")).unwrap();
            let claimed = inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    10_000,
                )
                .unwrap();
            assert_eq!(claimed.len(), 2);
        }
        {
            // Reopened: both commands are known and both are inside the
            // redelivery window, so a restarted gateway does not immediately
            // re-serve a command the agent already has.
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            assert_eq!(inbox.undelivered_count(), 0);
            assert!(
                inbox
                    .claim(
                        &target("agent-a"),
                        &acme_prod(),
                        DeliveryPolicy::default(),
                        12_000
                    )
                    .unwrap()
                    .is_empty()
            );
            // ... and past the window they come back, attempt count preserved.
            let again = inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    41_000,
                )
                .unwrap();
            assert_eq!(again.len(), 2);
            assert!(again.iter().all(|command| command.delivery_attempt == 2));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_persists_an_acknowledgement_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-ack-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-ack".to_owned(),
        };
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            inbox.record(&command("cmd-ack", "agent-a")).unwrap();
            inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    10_000,
                )
                .unwrap();
            assert_eq!(
                inbox
                    .acknowledge(&target("agent-a"), &key, 1, 11_000)
                    .unwrap(),
                AckResult::Acknowledged
            );
        }
        let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        assert_eq!(
            reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
            Ok(Some((DeliveryStatus::Acknowledged, 1)))
        );
        assert!(
            reopened
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    41_000
                )
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mirrors `file_inbox_persists_an_acknowledgement_across_restart`: a
    /// cancellation is journaled the same way an acknowledgement is, so a
    /// query for the command's status after a restart must still say
    /// `Cancelled` rather than falling back to "not found" -- which would be
    /// indistinguishable from a command_id that was never issued at all, a
    /// real audit-trail regression for a security-relevant control plane.
    #[test]
    fn file_inbox_persists_a_cancellation_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-cancel".to_owned(),
        };
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            inbox.record(&command("cmd-cancel", "agent-a")).unwrap();
            assert_eq!(inbox.cancel(&key, 5_000).unwrap(), CancelResult::Cancelled);
        }
        let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        assert_eq!(
            reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
            Ok(Some((DeliveryStatus::Cancelled, 0))),
            "a cancelled command's status must survive a restart, not silently become \
             indistinguishable from a command_id that was never issued"
        );
        // Still never deliverable after the restart.
        assert!(
            reopened
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    6_000
                )
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The refusal path (not just the success path) has to hold for the file
    /// backend too: a command already delivered once must never be
    /// cancellable, and the journal must show no `Cancelled` record for it --
    /// which this proves by reopening and checking `Delivered` survives.
    #[test]
    fn file_inbox_refuses_to_cancel_an_already_delivered_command() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-cancel-refused-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let key = InboxKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "cmd-cancel-refused".to_owned(),
        };
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            inbox
                .record(&command("cmd-cancel-refused", "agent-a"))
                .unwrap();
            let delivered = inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    1_000,
                )
                .unwrap();
            assert_eq!(delivered.len(), 1);
            let error = inbox.cancel(&key, 2_000).unwrap_err();
            assert_eq!(error.code, CommandErrorCode::AlreadyDelivered);
        }
        let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        assert_eq!(
            reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
            Ok(Some((DeliveryStatus::Delivered, 1))),
            "a refused cancellation must not have journaled anything"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_compaction_preserves_latest_delivery_state() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-compact-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let policy = DeliveryPolicy {
            redelivery_after: Duration::ZERO,
            max_attempts: 8,
        };
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
            inbox.record(&command("cmd-1", "agent-a")).unwrap();
            for attempt in 0..8 {
                assert_eq!(
                    inbox
                        .claim(&target("agent-a"), &acme_prod(), policy, attempt)
                        .unwrap()
                        .len(),
                    1
                );
            }
            let before = std::fs::metadata(&path).unwrap().len();
            inbox.compact().unwrap();
            let after = std::fs::metadata(&path).unwrap().len();
            assert!(after < before, "compaction must shrink repeated deliveries");
        }
        let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        assert_eq!(reopened.undelivered_count(), 0);
        assert!(
            reopened
                .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
                .unwrap()
                .is_empty(),
            "compaction must preserve the settled attempt ceiling"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_retention_preserves_then_expires_command_idempotency() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-retention-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inbox.jsonl");
        let policy = DeliveryPolicy {
            redelivery_after: Duration::ZERO,
            max_attempts: 1,
        };
        {
            let mut inbox = FileCommandInbox::open(&path, &dir, 2, 2).unwrap();
            inbox.record(&command("cmd-1", "agent-a")).unwrap();
            assert_eq!(
                inbox
                    .claim(&target("agent-a"), &acme_prod(), policy, 1)
                    .unwrap()
                    .len(),
                1
            );

            // Settlement removes the payload but retains the identity, so a
            // duplicate submission during the retention window is still a no-op.
            inbox.maintain(1_000, 100, 1).unwrap();
        }
        let mut inbox = FileCommandInbox::open(&path, &dir, 2, 2).unwrap();
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::AlreadyRecorded
        );

        // Once the tombstone itself expires, the identity can be reused and
        // is treated as a new command delivery.
        inbox.maintain(2_000, 100, 1).unwrap();
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::Recorded
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_inbox_refuses_a_path_outside_its_base() {
        let dir = std::env::temp_dir().join(format!("apex-inbox-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join("apex-inbox-escape.jsonl");
        assert!(FileCommandInbox::open(&outside, &dir, 64, 64).is_err());
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
        let mut inbox = FileCommandInbox::open(&dir.join("inbox.jsonl"), &dir, 64, 64).unwrap();
        let mut bad = command("cmd-1", "agent a");
        bad.action = "stop".to_owned();
        assert!(inbox.record(&bad).is_err());
        let mut bad_action = command("cmd-2", "agent-a");
        bad_action.action = "self_destruct".to_owned();
        assert!(inbox.record(&bad_action).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ListCommands ----------------------------------------------------

    fn list_query(after_sequence: u64, limit: usize) -> ListCommandsQuery<'static> {
        ListCommandsQuery {
            workspace_id: "acme",
            namespace_id: "prod",
            agent_id: None,
            state: None,
            after_sequence,
            limit,
            max_attempts: DEFAULT_MAX_DELIVERY_ATTEMPTS,
        }
    }

    /// A second page requested with the first page's cursor must return the
    /// *next* commands, not a repeat, and `has_more` must accurately track
    /// whether a further page exists.
    #[test]
    fn list_commands_pages_through_results_without_repeats_or_gaps() {
        let mut inbox = InMemoryCommandInbox::new(64, 64);
        for index in 0..5 {
            inbox
                .record(&command(&format!("cmd-{index}"), "agent-a"))
                .unwrap();
        }

        let first = inbox.list_commands(&list_query(0, 2)).unwrap();
        assert_eq!(
            first
                .commands
                .iter()
                .map(|c| c.command_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cmd-0", "cmd-1"]
        );
        assert!(first.has_more);

        let cursor = first.commands.last().unwrap().sequence;
        let second = inbox.list_commands(&list_query(cursor, 2)).unwrap();
        assert_eq!(
            second
                .commands
                .iter()
                .map(|c| c.command_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cmd-2", "cmd-3"]
        );
        assert!(second.has_more);
        assert_ne!(second.commands[0].command_id, first.commands[0].command_id);
        assert_ne!(second.commands[0].command_id, first.commands[1].command_id);

        let cursor = second.commands.last().unwrap().sequence;
        let third = inbox.list_commands(&list_query(cursor, 2)).unwrap();
        assert_eq!(third.commands.len(), 1);
        assert_eq!(third.commands[0].command_id, "cmd-4");
        assert!(
            !third.has_more,
            "the last page must not claim more are available"
        );
    }

    #[test]
    fn list_commands_filters_by_agent_id_and_by_state_and_can_combine_both() {
        let mut inbox = InMemoryCommandInbox::new(64, 64);
        inbox.record(&command("cmd-a", "agent-a")).unwrap();
        inbox.record(&command("cmd-b", "agent-b")).unwrap();
        // Deliver cmd-a so it is no longer Pending; cmd-b stays Pending.
        inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                1_000,
            )
            .unwrap();

        let agent_a_only = inbox
            .list_commands(&ListCommandsQuery {
                agent_id: Some("agent-a"),
                ..list_query(0, 16)
            })
            .unwrap();
        assert_eq!(agent_a_only.commands.len(), 1);
        assert_eq!(agent_a_only.commands[0].command_id, "cmd-a");
        assert_eq!(agent_a_only.commands[0].state, DeliveryStatus::Delivered);

        let pending_only = inbox
            .list_commands(&ListCommandsQuery {
                state: Some(DeliveryStatus::Pending),
                ..list_query(0, 16)
            })
            .unwrap();
        assert_eq!(pending_only.commands.len(), 1);
        assert_eq!(pending_only.commands[0].command_id, "cmd-b");

        // Combined: agent-a AND Delivered matches cmd-a; agent-a AND Pending
        // matches nothing, proving the two filters are ANDed, not ORed.
        let combined_match = inbox
            .list_commands(&ListCommandsQuery {
                agent_id: Some("agent-a"),
                state: Some(DeliveryStatus::Delivered),
                ..list_query(0, 16)
            })
            .unwrap();
        assert_eq!(combined_match.commands.len(), 1);
        assert_eq!(combined_match.commands[0].command_id, "cmd-a");

        let combined_empty = inbox
            .list_commands(&ListCommandsQuery {
                agent_id: Some("agent-a"),
                state: Some(DeliveryStatus::Pending),
                ..list_query(0, 16)
            })
            .unwrap();
        assert!(combined_empty.commands.is_empty());
    }

    #[test]
    fn list_commands_is_scoped_to_workspace_and_namespace() {
        let mut inbox = InMemoryCommandInbox::new(64, 64);
        inbox.record(&command("cmd-1", "agent-a")).unwrap(); // acme/prod, via `command()`.
        for (workspace_id, namespace_id) in
            [("other", "prod"), ("acme", "staging"), ("other", "staging")]
        {
            let page = inbox
                .list_commands(&ListCommandsQuery {
                    workspace_id,
                    namespace_id,
                    ..list_query(0, 16)
                })
                .unwrap();
            assert!(
                page.commands.is_empty(),
                "a query scoped to {workspace_id}/{namespace_id} must not see acme/prod's command"
            );
        }
    }

    /// `resolve_hold` is the sixth cooperative action, added on top of the
    /// same delivery mechanism `stop`/`pause`/`resume`/`inject`/`set_budget`
    /// already use. `is_recordable` (exercised here through
    /// `FileCommandInbox::record`, the only backend that enforces it) must
    /// accept it exactly like the other five, and a poll must deliver it like
    /// any other pending command.
    #[test]
    fn a_resolve_hold_command_is_recordable_and_deliverable() {
        let dir = std::env::temp_dir().join(format!(
            "apex-inbox-resolve-hold-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut inbox = FileCommandInbox::open(&dir.join("inbox.jsonl"), &dir, 64, 64).unwrap();
        let mut resolve = command("cmd-resolve-1", "agent-a");
        resolve.action = "resolve_hold".to_owned();
        assert_eq!(
            inbox.record(&resolve).unwrap(),
            RecordResult::Recorded,
            "a well-formed resolve_hold command must be recordable like any other action"
        );
        let delivered = inbox
            .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 1_000)
            .unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].command_id, "cmd-resolve-1");
        assert_eq!(delivered[0].action, "resolve_hold");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
