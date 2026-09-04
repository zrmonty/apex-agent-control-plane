//! Builds a validated `control` (`EventType::Control`) event envelope from an
//! accepted `ControlCommandRequest` and hands it to
//! `apex_durability::IngestRequest::from_validated_transport` -- the exact
//! same admission gate the ingest data path enforces. This module never
//! bypasses that gate; it only assembles the envelope fields that gate
//! requires (actor, version, integrity hash) from gateway-owned constants
//! plus caller-authenticated identity, so the payload shape it can never be
//! attacker-chosen to skip validation.

use apex_durability::{GatewayError, IngestRequest, canonical_event_hash};
use prost::Message;
use prost_types::Struct as ProstStruct;
use prost_types::value::Kind;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::OperatorCaller;
use crate::errors::CommandError;
use crate::inbox::PendingCommand;
use crate::proto;

/// Fixed provenance stamped on every control event this gateway emits. The
/// control gateway is not an instrumented agent runtime, so these are not
/// "requested vs effective model" attribution fields -- they identify the
/// OOB gateway itself as the event producer.
const GATEWAY_AGENT_CODE: &str = "apex-control-gateway";
const GATEWAY_PROMPT_REVISION: &str = "control-command-v1";
const GATEWAY_MODEL: &str = "n-a";

/// `reason_code` sentinel for a `force_stop` audit event that carried no
/// operator-supplied reason. See `build_control_request`'s comment on why
/// `force_stop` is recorded as `action: "stop"` in the shared, ingest-
/// validated `control` event, and why this marker is what keeps that
/// substitution honestly recoverable rather than silently lossy.
const FORCE_STOP_AUDIT_MARKER: &str = "apex.force_stop";
/// Prefix applied when the operator did supply a reason. Distinct from
/// [`FORCE_STOP_AUDIT_MARKER`] deliberately: an operator's own reason_code
/// could coincidentally *be* the marker string, but a still-valid
/// `is_scope_identifier` value starting with this prefix followed by a colon
/// is a far less likely accident, and either way this only affects the
/// narrow crash-recovery reconciliation path
/// (`pending_command_from_ingest_request`), never ordinary delivery.
const FORCE_STOP_AUDIT_PREFIX: &str = "apex.force_stop:";

mod time;

#[cfg(test)]
pub(crate) use time::{
    MAX_COMMAND_ID_AGE_MS, MAX_COMMAND_ID_FUTURE_SKEW_MS, civil_from_days, rfc3339_from_uuidv7,
};
pub(crate) use time::{
    command_millis_within_acceptance_window, format_rfc3339_micros, now_unix_millis,
    uuidv7_unix_millis,
};

pub struct ControlCommandInput {
    pub command_id: Option<String>,
    pub workspace_id: String,
    pub namespace_id: String,
    pub agent_id: String,
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub trace_id: String,
    pub action: proto::ControlAction,
    pub reason_code: Option<String>,
    pub parameters: Option<ProstStruct>,
}

impl ControlCommandInput {
    pub fn from_request(request: proto::ControlCommandRequest) -> Self {
        Self {
            command_id: request.command_id,
            workspace_id: request.workspace_id,
            namespace_id: request.namespace_id,
            agent_id: request.agent_id,
            run_id: request.run_id,
            parent_run_id: request.parent_run_id,
            trace_id: request.trace_id,
            action: proto::ControlAction::try_from(request.action)
                .unwrap_or(proto::ControlAction::Unspecified),
            reason_code: request.reason_code,
            parameters: request.parameters,
        }
    }
}

/// Everything an accepted command produces: the audit/trace side (the
/// `IngestRequest` destined for the outbox and the queryable trace) and the
/// delivery side (the [`PendingCommand`] the targeted agent will retrieve).
///
/// Built together, from one validation pass, deliberately. The two records
/// must describe the same command -- an operator reading the trace and an
/// agent receiving the instruction cannot be looking at different things --
/// and building the delivery record separately later is exactly how they would
/// drift.
#[derive(Debug)]
pub struct AcceptedCommand {
    pub command_id: String,
    pub request: IngestRequest,
    pub delivery: PendingCommand,
}

/// Rebuilds the delivery-side command from a durably accepted control event.
/// This is used by startup reconciliation when a process crashed after the
/// outbox commit but before the inbox write. The event has already passed the
/// ingest validator; the shape checks here defend the cross-store recovery
/// boundary rather than trusting a raw envelope.
pub fn pending_command_from_ingest_request(
    request: &IngestRequest,
) -> Result<PendingCommand, CommandError> {
    let envelope = apex_durability::proto::EventEnvelope::decode(request.envelope())
        .map_err(|_| CommandError::internal())?;
    if envelope.r#type != 9 {
        return Err(CommandError::internal());
    }
    let data = envelope.data.ok_or_else(CommandError::internal)?;
    let action = data
        .fields
        .get("action")
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            Kind::StringValue(value) => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(CommandError::internal)?;
    let reason_code = match data
        .fields
        .get("reason_code")
        .and_then(|value| value.kind.as_ref())
    {
        Some(Kind::StringValue(value)) => Some(value.clone()),
        Some(Kind::NullValue(_)) | None => None,
        _ => return Err(CommandError::internal()),
    };
    let parameters = match data
        .fields
        .get("parameters")
        .and_then(|value| value.kind.as_ref())
    {
        Some(Kind::StructValue(value)) => value.encode_to_vec(),
        _ => return Err(CommandError::internal()),
    };
    let scope = envelope.scope.ok_or_else(CommandError::internal)?;
    // Reverses `build_control_request`'s `force_stop` substitution (see its
    // own comment): a persisted `action: "stop"` event whose `reason_code`
    // carries the `force_stop:`/`force_stop` marker was really a
    // `force_stop`, and reconciliation must recover the *true* action, or a
    // process crash between the outbox commit and the inbox write would
    // silently recover a force-killed run's command as an ordinary
    // cooperative `stop` -- recorded correctly in the trace, delivered
    // wrongly to the one process (`apps/agent-supervisor`) that actually
    // acts on it.
    let (action, reason_code) =
        if action == "stop" && reason_code.as_deref() == Some(FORCE_STOP_AUDIT_MARKER) {
            ("force_stop".to_owned(), None)
        } else if let Some(original) = reason_code
            .as_deref()
            .filter(|_| action == "stop")
            .and_then(|value| value.strip_prefix(FORCE_STOP_AUDIT_PREFIX))
        {
            ("force_stop".to_owned(), Some(original.to_owned()))
        } else {
            (action, reason_code)
        };
    Ok(PendingCommand {
        command_id: envelope.event_id,
        workspace_id: scope.workspace_id,
        namespace_id: scope.namespace_id,
        agent_id: envelope.agent_id,
        run_id: envelope.run_id,
        trace_id: envelope.trace_id,
        action,
        reason_code,
        parameters,
        issued_at: envelope.timestamp,
        delivery_attempt: 0,
    })
}

/// Resolves a caller-supplied (or generated) `command_id` to the RFC 3339
/// timestamp the resulting `control` event will carry, applying the same
/// generate-or-validate and clock-window rules `build_control_request` always
/// has.
///
/// Factored out so [`crate::service`]'s dual-approval gate for `force_stop`
/// can resolve and bound-check a `command_id` -- and therefore know what
/// timestamp the eventual `control` event will carry -- for the *first*
/// approval, before `build_control_request` is ever called for that command.
/// The two approvals must agree on one `command_id`; deriving its timestamp
/// identically in both places is what keeps that agreement meaningful rather
/// than accidental.
pub(crate) fn resolve_command_id_and_timestamp(
    command_id: Option<String>,
) -> Result<(String, String), CommandError> {
    let command_id = match command_id {
        Some(id) if !id.is_empty() => id,
        _ => Uuid::now_v7().to_string(),
    };

    // The envelope timestamp is derived from the command_id's own embedded
    // UUIDv7 millisecond clock, not the wall clock at call time. That makes
    // the canonicalized envelope -- and therefore its integrity hash --
    // deterministic for a given command_id. Idempotent replay of the same
    // command_id with the same fields must produce byte-identical envelopes
    // so the outbox recognizes it as `AlreadyPending`/`AlreadyComplete`
    // rather than a spurious `IDEMPOTENCY_CONFLICT` caused only by two
    // submissions landing in different microseconds.
    //
    // Determinism alone is not enough. `command_id` is entirely caller-chosen,
    // so deriving the timestamp from it without a bound would let any holder
    // of a valid operator credential stamp a `stop`/`inject`/`set_budget`
    // command with an arbitrary audit time -- backdating it before an
    // incident window, or postdating it out of a retention query. The emitted
    // `control` event is the audit record for that command, so the embedded
    // clock must stay inside a bounded window around the gateway's own.
    let command_millis = uuidv7_unix_millis(&command_id).ok_or_else(|| {
        CommandError::new(
            crate::errors::CommandErrorCode::InvalidCommand,
            "command_id must be a canonical lowercase UUIDv7.",
        )
    })?;
    if !command_millis_within_acceptance_window(command_millis, now_unix_millis()) {
        return Err(CommandError::new(
            crate::errors::CommandErrorCode::InvalidCommand,
            "command_id's embedded UUIDv7 timestamp is outside the accepted clock window. Generate the command_id at submission time.",
        ));
    }
    let timestamp = format_rfc3339_micros(u128::from(command_millis) * 1_000);
    Ok((command_id, timestamp))
}

/// Validates the caller's scope and builds the outbox-ready `IngestRequest`
/// for a control command, together with the delivery record its target agent
/// will retrieve. Returns the generated/validated `command_id` alongside them
/// so the caller can echo it in the response.
pub fn build_control_request(
    input: ControlCommandInput,
    operator: &OperatorCaller,
) -> Result<AcceptedCommand, CommandError> {
    if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
        return Err(CommandError::scope_denied());
    }
    let action_name = action_name(input.action).ok_or_else(|| {
        CommandError::new(
            crate::errors::CommandErrorCode::InvalidCommand,
            "action must be one of stop, pause, resume, inject, set_budget, resolve_hold, force_stop.",
        )
    })?;

    let (command_id, timestamp) = resolve_command_id_and_timestamp(input.command_id)?;

    // Captured before the envelope consumes the input. The delivery record
    // carries the operator's `parameters` object prost-encoded and otherwise
    // untouched: `inject.content` is explicitly untrusted data, so it must
    // reach the runtime byte-identical to what was recorded rather than being
    // round-tripped through any interpreting representation.
    let delivery = PendingCommand {
        command_id: command_id.clone(),
        workspace_id: input.workspace_id.clone(),
        namespace_id: input.namespace_id.clone(),
        agent_id: input.agent_id.clone(),
        run_id: input.run_id.clone(),
        trace_id: input.trace_id.clone(),
        action: action_name.to_owned(),
        reason_code: input.reason_code.clone(),
        parameters: input
            .parameters
            .as_ref()
            .map(prost::Message::encode_to_vec)
            .unwrap_or_default(),
        issued_at: timestamp.clone(),
        delivery_attempt: 0,
    };

    // `apex_durability::validation::control::validate_control_data` --
    // deliberately out of scope for this pass, see this crate's own
    // instruction not to modify `apps/event-ingest` -- hard-codes the set of
    // action names and the single `enforcement` literal a `control` event's
    // `data` may carry, predating `force_stop` by design (ADR-0005
    // explicitly deferred forced stop past v1). Rather than fabricate a
    // schema slot that validator does not know about, the *audit* event for
    // a `force_stop` is recorded under the closest existing category,
    // `"stop"`, with `enforcement` left at that validator's only accepted
    // value (see `build_control_data`). Neither is quite accurate taken
    // alone for a kill enacted from outside the agent process entirely --
    // what keeps that honest instead of silently misleading is
    // `reason_code`: free text, not constrained by that validator's fixed
    // action vocabulary, always prefixed `force_stop:` for this one action
    // so the queryable trace and any audit tooling reading it can tell a
    // `force_stop` apart from an ordinary cooperative `stop` at a glance.
    // This substitution affects only the shared, ingest-validated audit
    // event: `delivery` above -- what `apps/agent-supervisor` actually polls
    // and acts on -- already carries the true `force_stop` action and the
    // operator's own, unprefixed `reason_code` throughout.
    let is_force_stop = action_name == "force_stop";
    let audit_action_name = if is_force_stop { "stop" } else { action_name };
    let audit_reason_code = if is_force_stop {
        Some(match input.reason_code.as_deref() {
            Some(reason) => format!("{FORCE_STOP_AUDIT_PREFIX}{reason}"),
            None => FORCE_STOP_AUDIT_MARKER.to_owned(),
        })
    } else {
        input.reason_code.clone()
    };
    let data = build_control_data(
        audit_action_name,
        audit_reason_code.as_deref(),
        input.parameters,
    );

    let envelope = apex_durability::proto::EventEnvelope {
        event_id: command_id.clone(),
        timestamp,
        r#type: 9, // EventType::CONTROL
        agent_id: input.agent_id,
        run_id: input.run_id,
        parent_run_id: input.parent_run_id,
        trace_id: input.trace_id,
        scope: Some(apex_durability::proto::Scope {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            agent_group_ids: vec![],
        }),
        actor: Some(apex_durability::proto::Actor {
            r#type: 1, // ActorType::USER -- a human/automated operator, not the agent workload.
            id: operator.subject().to_owned(),
        }),
        version: Some(apex_durability::proto::Version {
            agent_code: GATEWAY_AGENT_CODE.to_owned(),
            prompt: GATEWAY_PROMPT_REVISION.to_owned(),
            model: GATEWAY_MODEL.to_owned(),
        }),
        data: Some(data),
        integrity: None, // filled in below once the rest of the envelope is fixed.
        schema_version: 1,
    };

    let event_hash = canonical_event_hash(&envelope_with_placeholder_integrity(&envelope))
        .map_err(|error| CommandError::from_gateway_error(&error))?;
    let mut envelope = envelope;
    envelope.integrity = Some(apex_durability::proto::Integrity {
        prev_hash: None,
        event_hash,
    });

    let request = IngestRequest::from_validated_transport(envelope)
        .map_err(|error: GatewayError| CommandError::from_gateway_error(&error))?;
    Ok(AcceptedCommand {
        command_id,
        request,
        delivery,
    })
}

/// `canonical_event_hash` reads `integrity.prev_hash` (always null at the
/// control-command chain root, since these are not chained per-agent
/// events) but does not read `event_hash` itself, so a placeholder
/// `Integrity` with an empty hash is enough to compute the real hash.
fn envelope_with_placeholder_integrity(
    envelope: &apex_durability::proto::EventEnvelope,
) -> apex_durability::proto::EventEnvelope {
    let mut clone = envelope.clone();
    clone.integrity = Some(apex_durability::proto::Integrity {
        prev_hash: None,
        event_hash: String::new(),
    });
    clone
}

/// Crate-visible so `service.rs` can validate a `SubmitBulkCommand` request's
/// single, request-level `action` once, up front, rather than letting every
/// target independently rediscover the same "action is unspecified" failure
/// through [`build_control_request`].
pub(crate) fn action_name(action: proto::ControlAction) -> Option<&'static str> {
    Some(match action {
        proto::ControlAction::Stop => "stop",
        proto::ControlAction::Pause => "pause",
        proto::ControlAction::Resume => "resume",
        proto::ControlAction::Inject => "inject",
        proto::ControlAction::SetBudget => "set_budget",
        proto::ControlAction::ResolveHold => "resolve_hold",
        proto::ControlAction::ForceStop => "force_stop",
        proto::ControlAction::Unspecified => return None,
    })
}

fn build_control_data(
    action: &str,
    reason_code: Option<&str>,
    parameters: Option<ProstStruct>,
) -> ProstStruct {
    let mut fields = prost_types::Struct::default().fields;
    fields.insert("action".to_owned(), string_value(action));
    // Always "cooperative": `apex_durability::validation::control::validate_control_data`
    // (out of scope for this pass -- see `build_control_request`'s own
    // comment on why `force_stop` is recorded as `action: "stop"` here) hard-
    // codes this as the *only* literal it accepts for every control action,
    // `force_stop` included by necessity.
    fields.insert("enforcement".to_owned(), string_value("cooperative"));
    fields.insert(
        "reason_code".to_owned(),
        match reason_code {
            Some(value) => string_value(value),
            None => prost_types::Value {
                kind: Some(Kind::NullValue(0)),
            },
        },
    );
    fields.insert(
        "parameters".to_owned(),
        prost_types::Value {
            kind: Some(Kind::StructValue(parameters.unwrap_or_default())),
        },
    );
    ProstStruct { fields }
}

fn string_value(value: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(Kind::StringValue(value.to_owned())),
    }
}

/// Validates a caller-supplied `SubmitBulkCommand.bulk_id`, or mints a fresh
/// one when omitted, and returns its embedded UUIDv7 millisecond clock
/// alongside it.
///
/// Same grammar and the same acceptance window as `command_id` in
/// [`build_control_request`] -- deliberately: `bulk_id` plays exactly the
/// `command_id` role for a bulk call, one level up. Every per-target
/// `command_id` a bulk call produces is deterministically derived from this
/// validated id (see [`derive_target_command_id`]), so validating it here,
/// once, is what lets every derived id inherit a trustworthy, bounded audit
/// timestamp without re-deriving and re-checking one per target.
pub(crate) fn validate_bulk_id(bulk_id: Option<String>) -> Result<(String, u64), CommandError> {
    let bulk_id = match bulk_id {
        Some(id) if !id.is_empty() => id,
        _ => Uuid::now_v7().to_string(),
    };
    let millis = uuidv7_unix_millis(&bulk_id).ok_or_else(|| {
        CommandError::new(
            crate::errors::CommandErrorCode::InvalidCommand,
            "bulk_id must be a canonical lowercase UUIDv7.",
        )
    })?;
    if !command_millis_within_acceptance_window(millis, now_unix_millis()) {
        return Err(CommandError::new(
            crate::errors::CommandErrorCode::InvalidCommand,
            "bulk_id's embedded UUIDv7 timestamp is outside the accepted clock window. Generate the bulk_id at submission time.",
        ));
    }
    Ok((bulk_id, millis))
}

/// Deterministically derives one bulk target's `command_id` from a validated
/// `bulk_id` and that target's own identity fields.
///
/// # Why derived rather than operator-supplied per target
///
/// `SubmitCommand` lets an operator choose `command_id` because a human
/// issuing one command can reasonably generate and remember one idempotency
/// key. A bulk call fanning out to dozens of targets is exactly the case
/// where that stops being reasonable: the point of this RPC is that the
/// operator supplies the target list once, not the target list plus a
/// matching list of idempotency keys. Deriving each target's id from
/// `bulk_id` gives the same retry safety `command_id` gives a single
/// command -- resubmitting the same `bulk_id` against the same targets
/// reproduces the exact same per-target ids, which the existing
/// outbox/inbox idempotency machinery (unchanged; see `outbox.rs`/
/// `inbox.rs`) then recognizes as duplicates on its own -- without asking the
/// operator to track anything beyond the one id this call already hands
/// back in [`proto::SubmitBulkCommandResponse::bulk_id`].
///
/// This also means two identical targets accidentally listed twice in one
/// bulk call collapse to the same derived `command_id`: the second occurrence
/// is reported as an accepted duplicate rather than double-enqueuing the
/// command, with no special-casing required here.
///
/// # Why this is still a valid, trustworthy UUIDv7
///
/// The embedded millisecond timestamp is `bulk_id`'s own, already checked
/// against the gateway's acceptance window by [`validate_bulk_id`]; this
/// function never invents a timestamp of its own, so a derived id cannot be
/// used to backdate or postdate the audit record any differently than a
/// single `command_id` already could. Only the random/counter bits differ per
/// target, seeded from a SHA-256 digest of `bulk_id` and the target's own
/// scope/agent/run/trace identity, each field separated by a `0x00` byte so
/// no concatenation of two fields can collide with a different split of the
/// same bytes -- deterministic, and as collision-resistant as any other
/// SHA-256-derived value in this crate.
/// `uuid::Builder::from_unix_timestamp_millis` sets the version/variant bits
/// correctly, so the result satisfies the exact same canonical-lowercase-
/// UUIDv7 grammar [`build_control_request`] already enforces for a
/// caller-supplied `command_id`.
pub(crate) fn derive_target_command_id(
    bulk_id: &str,
    bulk_millis: u64,
    target: &proto::BulkCommandTarget,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bulk_id.as_bytes());
    for field in [
        target.workspace_id.as_str(),
        target.namespace_id.as_str(),
        target.agent_id.as_str(),
        target.run_id.as_str(),
        target.trace_id.as_str(),
    ] {
        hasher.update([0u8]);
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let mut random_bytes = [0u8; 10];
    random_bytes.copy_from_slice(&digest[..10]);
    uuid::Builder::from_unix_timestamp_millis(bulk_millis, &random_bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

#[cfg(test)]
mod tests;
