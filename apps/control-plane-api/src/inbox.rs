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
    /// `set_budget`, `resolve_hold`, `force_stop`.
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

    /// Fallible diagnostic form. Backends with remote storage override this
    /// so a query failure cannot be mistaken for a healthy zero.
    fn try_undelivered_count(&mut self) -> Result<usize, CommandError> {
        Ok(self.undelivered_count())
    }

    /// Fallible diagnostic form. Local backends inherit the infallible count;
    /// remote backends must surface transport/query failures.
    fn try_pending_count(&mut self) -> Result<usize, CommandError> {
        Ok(self.pending_count())
    }

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

    fn try_undelivered_count(&mut self) -> Result<usize, CommandError> {
        (**self).try_undelivered_count()
    }

    fn try_pending_count(&mut self) -> Result<usize, CommandError> {
        (**self).try_pending_count()
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
            "stop"
                | "pause"
                | "resume"
                | "inject"
                | "set_budget"
                | "resolve_hold"
                | "force_stop"
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

mod backend;
mod file;
mod state;

pub use backend::ControlInboxBackend;
pub use file::FileCommandInbox;
pub use state::InMemoryCommandInbox;

#[cfg(test)]
mod tests;
