//! Two-party approval gate for `force_stop`, and *only* `force_stop`.
//!
//! Every other action (`stop`, `pause`, `resume`, `inject`, `set_budget`)
//! keeps the single-operator path `service::submit_command` has always had:
//! one authenticated operator, in scope, is sufficient. `force_stop` is
//! different because of what it does once delivered -- it does not ask the
//! agent's own SDK process to cooperate, it has `apps/agent-supervisor` kill
//! the agent's whole OS process group from outside that process entirely
//! (see that crate's docs). An action with that much blast radius and no
//! cooperative undo is exactly the case
//! `Ownership and Team Authorization.md`'s separation-of-duty table names
//! under "Production forced stop or bulk control": *authorized operator plus
//! policy-required second approver*. This module is that second approver
//! requirement, enforced before the command is ever durably recorded --
//! never after.
//!
//! # Shape
//!
//! There is deliberately no new RPC. The existing `SubmitCommand` is reused
//! for both approvals, keyed on the (caller-supplied-or-generated)
//! `command_id`: the first operator to submit a `force_stop` for a given
//! `command_id` registers the first approval and gets back
//! `awaiting_second_approval: true` with *nothing* recorded yet -- not in the
//! outbox, not in the inbox, not observable by the target run in any way. A
//! second, *distinct* operator subject must submit `SubmitCommand` again with
//! the identical `command_id` and identical command fields; only then does
//! `service::ControlGatewayService::submit_force_stop` call through to the
//! same `build_control_request`/outbox/inbox path every other action uses.
//! Mirrors the shape `Signed Evidence Bundles.md` documents for its own
//! two-party export-approval gate (that feature's v2 scope, not yet
//! implemented in code anywhere in this repository as of this pass) rather
//! than inventing a third pattern for "two humans must agree" in this
//! codebase.
//!
//! The same operator submitting twice does **not** satisfy the requirement --
//! that would reduce "two distinct operators" to "one operator, twice",
//! which is not the control this exists to provide.
//!
//! # Durability, honestly stated
//!
//! This gate's pending-approval state is **in-memory only**, process-local,
//! and lost on restart -- unlike every other piece of state this gateway
//! holds (the outbox, the inbox), which are durable by design. A gateway
//! restart between the first and second approval means the first operator
//! must approve again. This is a real, deliberate v1 limitation, not an
//! oversight: the property that actually matters for the security model --
//! that a `force_stop` is never recorded into the durable, agent-visible
//! inbox on a single operator's say-so -- holds regardless, because nothing
//! is written to durable storage until the second, distinct approval lands.
//! Losing an in-flight first approval to a restart is a availability
//! inconvenience (approve again), never a safety gap (a lost approval can
//! never turn into an unapproved `force_stop` being enacted). A future pass
//! wanting cross-restart approval survival should persist this table the
//! same way the inbox persists delivery state, rather than widening what
//! "recorded" means for an unapproved command.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use prost::Message;
use sha2::{Digest, Sha256};

use crate::envelope::ControlCommandInput;
use crate::errors::CommandError;

/// How long an unresolved first approval is held before it is discarded and
/// a subsequent submission for the same `command_id` starts a fresh
/// approval cycle. Long enough that a human paging a second operator is not
/// racing the clock; bounded so an operator who submits a `force_stop` and
/// never follows up (or an attacker probing the gate) cannot grow this table
/// without limit.
pub(crate) const APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);

/// Bounded for the same reason every other process-local table in this
/// gateway is (`OperatorTokenAuthenticator`'s failure buckets,
/// `ControlGatewayService`'s admission buckets): unbounded growth keyed on a
/// caller-influenced value (`command_id` here) is a memory-exhaustion vector
/// in its own right, independent of whatever the caller was actually trying
/// to do.
const MAX_TRACKED_APPROVALS: usize = 4096;

/// Identifies one candidate `force_stop` awaiting its second approval.
/// `command_id` is scoped by workspace/namespace for the same reason every
/// other command identity in this crate is: two tenants must never be able
/// to collide on an approval slot by choosing the same `command_id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ApprovalKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub command_id: String,
}

#[derive(Debug, Clone)]
struct PendingApproval {
    /// Hash of the semantic command fields (everything the eventual
    /// `control` event would carry, minus identity/timestamp fields already
    /// captured in the key). The second submission must match, or it is
    /// describing a *different* command under a reused `command_id` -- the
    /// same idempotency-conflict shape every other action already enforces,
    /// applied one step earlier here.
    fingerprint: [u8; 32],
    first_operator_subject: String,
    created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalOutcome {
    /// First approval recorded. Nothing durable has happened yet.
    AwaitingSecond,
    /// The same operator subject that holds the first approval submitted
    /// again. Not progress: still awaiting a *distinct* second approver.
    AlreadyApprovedBySameOperator,
    /// A second, distinct operator approved a request whose fields match the
    /// first exactly. The caller may now build and durably record the
    /// command.
    Approved,
    /// A second submission under the same `command_id` described different
    /// command fields than the first approval did.
    FieldMismatch,
}

/// Process-local pending-approval table. See the module docs for why
/// process-local (not durable) is a deliberate, safety-preserving choice for
/// v1.
pub(crate) struct DualApprovalGate {
    pending: Mutex<HashMap<ApprovalKey, PendingApproval>>,
}

impl DualApprovalGate {
    pub(crate) fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Records one operator's approval of `key`/`fingerprint` and reports
    /// whether that satisfies the two-distinct-operator requirement.
    ///
    /// A poisoned lock fails closed (`CommandError::internal`), the same
    /// discipline every other shared table in this crate applies -- an
    /// approval gate that could be forced into an unthrottled or
    /// always-approve state by a panicked holder would defeat the point of
    /// having one.
    pub(crate) fn submit(
        &self,
        key: ApprovalKey,
        fingerprint: [u8; 32],
        operator_subject: &str,
    ) -> Result<ApprovalOutcome, CommandError> {
        let Ok(mut pending) = self.pending.lock() else {
            return Err(CommandError::internal());
        };
        let now = Instant::now();
        pending.retain(|_, entry| now.duration_since(entry.created_at) < APPROVAL_TTL);
        if let Some(entry) = pending.get(&key) {
            if entry.fingerprint != fingerprint {
                return Ok(ApprovalOutcome::FieldMismatch);
            }
            if entry.first_operator_subject == operator_subject {
                return Ok(ApprovalOutcome::AlreadyApprovedBySameOperator);
            }
            pending.remove(&key);
            return Ok(ApprovalOutcome::Approved);
        }
        if pending.len() >= MAX_TRACKED_APPROVALS {
            return Err(CommandError::rate_limited());
        }
        pending.insert(
            key,
            PendingApproval {
                fingerprint,
                first_operator_subject: operator_subject.to_owned(),
                created_at: now,
            },
        );
        Ok(ApprovalOutcome::AwaitingSecond)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.pending.lock().map(|guard| guard.len()).unwrap_or(0)
    }
}

impl Default for DualApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Hashes the semantic content of a `force_stop` request: everything the
/// resulting `control` event would carry except the identity fields already
/// captured in [`ApprovalKey`] and the caller-controlled `command_id` itself.
/// Two submissions with the same `command_id` must describe the same command
/// to both count toward one approval.
pub(crate) fn fingerprint(input: &ControlCommandInput) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(input.agent_id.as_bytes());
    field(input.run_id.as_bytes());
    field(input.parent_run_id.as_deref().unwrap_or_default().as_bytes());
    field(input.trace_id.as_bytes());
    field(&(input.action as i32).to_le_bytes());
    field(input.reason_code.as_deref().unwrap_or_default().as_bytes());
    field(
        &input
            .parameters
            .as_ref()
            .map(Message::encode_to_vec)
            .unwrap_or_default(),
    );
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;

    fn key(command_id: &str) -> ApprovalKey {
        ApprovalKey {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: command_id.to_owned(),
        }
    }

    fn input(agent_id: &str) -> ControlCommandInput {
        ControlCommandInput {
            command_id: None,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: agent_id.to_owned(),
            run_id: "run-1".to_owned(),
            parent_run_id: None,
            trace_id: "trace-1".to_owned(),
            action: proto::ControlAction::ForceStop,
            reason_code: Some("incident-42".to_owned()),
            parameters: None,
        }
    }

    #[test]
    fn a_single_operator_never_reaches_approved() {
        let gate = DualApprovalGate::new();
        let fp = fingerprint(&input("agent-1"));
        assert_eq!(
            gate.submit(key("cmd-1"), fp, "operator:alice").unwrap(),
            ApprovalOutcome::AwaitingSecond
        );
        // Same operator, repeated: still not approved.
        for _ in 0..5 {
            assert_eq!(
                gate.submit(key("cmd-1"), fp, "operator:alice").unwrap(),
                ApprovalOutcome::AlreadyApprovedBySameOperator
            );
        }
        assert_eq!(gate.tracked(), 1);
    }

    #[test]
    fn a_second_distinct_operator_approves_and_clears_the_entry() {
        let gate = DualApprovalGate::new();
        let fp = fingerprint(&input("agent-1"));
        assert_eq!(
            gate.submit(key("cmd-2"), fp, "operator:alice").unwrap(),
            ApprovalOutcome::AwaitingSecond
        );
        assert_eq!(
            gate.submit(key("cmd-2"), fp, "operator:bob").unwrap(),
            ApprovalOutcome::Approved
        );
        // The slot is cleared: a third submission starts a fresh cycle
        // rather than being treated as an immediate re-approval.
        assert_eq!(gate.tracked(), 0);
        assert_eq!(
            gate.submit(key("cmd-2"), fp, "operator:carol").unwrap(),
            ApprovalOutcome::AwaitingSecond
        );
    }

    #[test]
    fn a_second_submission_describing_different_fields_is_a_mismatch_not_an_approval() {
        let gate = DualApprovalGate::new();
        let first = fingerprint(&input("agent-1"));
        let different = fingerprint(&input("agent-2"));
        assert_eq!(
            gate.submit(key("cmd-3"), first, "operator:alice").unwrap(),
            ApprovalOutcome::AwaitingSecond
        );
        assert_eq!(
            gate.submit(key("cmd-3"), different, "operator:bob").unwrap(),
            ApprovalOutcome::FieldMismatch
        );
        // The original pending approval is left intact for a legitimate
        // second approver.
        assert_eq!(
            gate.submit(key("cmd-3"), first, "operator:bob").unwrap(),
            ApprovalOutcome::Approved
        );
    }

    #[test]
    fn distinct_command_ids_are_independent() {
        let gate = DualApprovalGate::new();
        let fp = fingerprint(&input("agent-1"));
        gate.submit(key("cmd-a"), fp, "operator:alice").unwrap();
        gate.submit(key("cmd-b"), fp, "operator:alice").unwrap();
        assert_eq!(gate.tracked(), 2);
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive_to_every_semantic_field() {
        let base = input("agent-1");
        assert_eq!(fingerprint(&base), fingerprint(&input("agent-1")));

        let mut variant = input("agent-1");
        variant.run_id = "run-2".to_owned();
        assert_ne!(fingerprint(&base), fingerprint(&variant));

        let mut variant = input("agent-1");
        variant.reason_code = Some("different".to_owned());
        assert_ne!(fingerprint(&base), fingerprint(&variant));

        let mut variant = input("agent-1");
        variant.parent_run_id = Some("parent-1".to_owned());
        assert_ne!(fingerprint(&base), fingerprint(&variant));
    }
}
