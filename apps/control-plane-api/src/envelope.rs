//! Builds a validated `control` (`EventType::Control`) event envelope from an
//! accepted `ControlCommandRequest` and hands it to
//! `apex_event_ingest::IngestRequest::from_validated_transport` -- the exact
//! same admission gate the ingest data path enforces. This module never
//! bypasses that gate; it only assembles the envelope fields that gate
//! requires (actor, version, integrity hash) from gateway-owned constants
//! plus caller-authenticated identity, so the payload shape it can never be
//! attacker-chosen to skip validation.

use std::time::{SystemTime, UNIX_EPOCH};

use apex_event_ingest::{GatewayError, IngestRequest, canonical_event_hash};
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

/// How far ahead of the gateway's own clock a caller-supplied `command_id`'s
/// embedded UUIDv7 timestamp may sit. This only absorbs ordinary clock skew
/// between an operator console and the gateway.
const MAX_COMMAND_ID_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
/// How far behind the gateway's own clock that same embedded timestamp may
/// sit. Generous enough that an idempotent retry after a long outage still
/// resolves to `duplicate` rather than a spurious rejection, but bounded so
/// the emitted `control` event's audit timestamp cannot be set arbitrarily.
const MAX_COMMAND_ID_AGE_MS: u64 = 24 * 60 * 60 * 1_000;

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
    let envelope = apex_event_ingest::proto::EventEnvelope::decode(request.envelope())
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
    let reason_code = match data.fields.get("reason_code").and_then(|value| value.kind.as_ref()) {
        Some(Kind::StringValue(value)) => Some(value.clone()),
        Some(Kind::NullValue(_)) | None => None,
        _ => return Err(CommandError::internal()),
    };
    let parameters = match data.fields.get("parameters").and_then(|value| value.kind.as_ref()) {
        Some(Kind::StructValue(value)) => value.encode_to_vec(),
        _ => return Err(CommandError::internal()),
    };
    let scope = envelope.scope.ok_or_else(CommandError::internal)?;
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
            "action must be one of stop, pause, resume, inject, set_budget.",
        )
    })?;

    let command_id = match input.command_id {
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

    let data = build_control_data(action_name, input.reason_code.as_deref(), input.parameters);

    let envelope = apex_event_ingest::proto::EventEnvelope {
        event_id: command_id.clone(),
        timestamp,
        r#type: 9, // EventType::CONTROL
        agent_id: input.agent_id,
        run_id: input.run_id,
        parent_run_id: input.parent_run_id,
        trace_id: input.trace_id,
        scope: Some(apex_event_ingest::proto::Scope {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            agent_group_ids: vec![],
        }),
        actor: Some(apex_event_ingest::proto::Actor {
            r#type: 1, // ActorType::USER -- a human/automated operator, not the agent workload.
            id: operator.subject().to_owned(),
        }),
        version: Some(apex_event_ingest::proto::Version {
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
    envelope.integrity = Some(apex_event_ingest::proto::Integrity {
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
    envelope: &apex_event_ingest::proto::EventEnvelope,
) -> apex_event_ingest::proto::EventEnvelope {
    let mut clone = envelope.clone();
    clone.integrity = Some(apex_event_ingest::proto::Integrity {
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
        proto::ControlAction::Unspecified => return None,
    })
}

fn build_control_data(
    action: &str,
    reason_code: Option<&str>,
    parameters: Option<ProstStruct>,
) -> ProstStruct {
    let mut fields = prost_types::Struct::default().fields;
    fields.insert(
        "action".to_owned(),
        string_value(action),
    );
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

/// Extracts the embedded 48-bit millisecond Unix timestamp from a UUIDv7.
///
/// Deliberately stricter than `Uuid::parse_str` alone: the value must already
/// be in the canonical lowercase hyphenated form the ingest boundary accepts
/// (`is_lowercase_uuidv7`). `parse_str` also accepts braced, URN, simple, and
/// uppercase spellings, so without this round-trip check a `command_id` could
/// derive a timestamp here through one grammar and then be judged by a
/// different one downstream.
fn uuidv7_unix_millis(command_id: &str) -> Option<u64> {
    let uuid = Uuid::parse_str(command_id).ok()?;
    if uuid.get_version_num() != 7 || uuid.hyphenated().to_string() != command_id {
        return None;
    }
    let (secs, nanos) = uuid.get_timestamp()?.to_unix();
    u64::try_from((secs as u128) * 1_000 + (nanos as u128) / 1_000_000).ok()
}

/// True when a `command_id`'s embedded clock is close enough to the
/// gateway's own clock to be a plausible submission time rather than a
/// chosen audit timestamp.
fn command_millis_within_acceptance_window(command_millis: u64, now_millis: u64) -> bool {
    if command_millis > now_millis {
        command_millis - now_millis <= MAX_COMMAND_ID_FUTURE_SKEW_MS
    } else {
        now_millis - command_millis <= MAX_COMMAND_ID_AGE_MS
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

/// Wall-clock milliseconds since the Unix epoch.
///
/// Shared with [`crate::service`], which needs the same clock for the inbox's
/// redelivery-window arithmetic. One reader, so a command's issued-at and its
/// delivery bookkeeping cannot disagree about what "now" means.
pub(crate) fn now_unix_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Derives the RFC 3339 microsecond timestamp a given `command_id` maps to.
/// Returns `None` for anything that is not a canonical lowercase UUIDv7.
/// `build_control_request` composes `uuidv7_unix_millis` and
/// `format_rfc3339_micros` directly so it can bound the value first; this
/// keeps the end-to-end mapping expressible for the tests that pin it.
#[cfg(test)]
fn rfc3339_from_uuidv7(command_id: &str) -> Option<String> {
    uuidv7_unix_millis(command_id)
        .map(|millis| format_rfc3339_micros(u128::from(millis) * 1_000))
}

fn format_rfc3339_micros(total_micros: u128) -> String {
    let secs = (total_micros / 1_000_000) as i64;
    let micros = (total_micros % 1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z"
    )
}

/// Howard Hinnant's `civil_from_days`: converts a day count relative to the
/// Unix epoch into a proleptic-Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_timestamps_match_the_ingest_boundary_format() {
        let timestamp = rfc3339_from_uuidv7(&Uuid::now_v7().to_string())
            .expect("a freshly generated UUIDv7 must yield a timestamp");
        assert_eq!(timestamp.len(), 27);
        assert!(timestamp.ends_with('Z'));
        assert_eq!(timestamp.as_bytes()[4], b'-');
        assert_eq!(timestamp.as_bytes()[19], b'.');
    }

    #[test]
    fn acceptance_window_bounds_backdating_and_postdating_symmetrically() {
        let now = 1_800_000_000_000_u64;
        assert!(command_millis_within_acceptance_window(now, now));
        assert!(command_millis_within_acceptance_window(
            now + MAX_COMMAND_ID_FUTURE_SKEW_MS,
            now
        ));
        assert!(!command_millis_within_acceptance_window(
            now + MAX_COMMAND_ID_FUTURE_SKEW_MS + 1,
            now
        ));
        assert!(command_millis_within_acceptance_window(
            now - MAX_COMMAND_ID_AGE_MS,
            now
        ));
        assert!(!command_millis_within_acceptance_window(
            now - MAX_COMMAND_ID_AGE_MS - 1,
            now
        ));
        assert!(!command_millis_within_acceptance_window(0, now));
    }

    #[test]
    fn uuidv7_unix_millis_requires_the_canonical_lowercase_spelling() {
        let canonical = uuidv7_with_millis(1_700_000_000_000);
        assert_eq!(
            uuidv7_unix_millis(&canonical),
            Some(1_700_000_000_000),
            "canonical form must parse"
        );
        // Same UUID, non-canonical spellings that `Uuid::parse_str` accepts
        // but the ingest boundary's `is_lowercase_uuidv7` does not.
        assert!(uuidv7_unix_millis(&canonical.to_uppercase()).is_none());
        assert!(uuidv7_unix_millis(&format!("{{{canonical}}}")).is_none());
        assert!(uuidv7_unix_millis(&format!("urn:uuid:{canonical}")).is_none());
        assert!(uuidv7_unix_millis(&canonical.replace('-', "")).is_none());
    }

    #[test]
    fn civil_from_days_matches_known_epoch_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn action_name_covers_every_defined_action_and_rejects_unspecified() {
        assert_eq!(action_name(proto::ControlAction::Stop), Some("stop"));
        assert_eq!(action_name(proto::ControlAction::SetBudget), Some("set_budget"));
        assert_eq!(action_name(proto::ControlAction::Unspecified), None);
    }

    #[test]
    fn rfc3339_from_uuidv7_is_deterministic_for_the_same_id() {
        let id = Uuid::now_v7().to_string();
        let first = rfc3339_from_uuidv7(&id).unwrap();
        let second = rfc3339_from_uuidv7(&id).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 27);
    }

    #[test]
    fn rfc3339_from_uuidv7_rejects_a_non_v7_uuid() {
        // A v4 UUID (random, no embedded timestamp) must fall back to `None`.
        let v4 = "018f0000-0000-4000-8000-000000000000";
        assert!(rfc3339_from_uuidv7(v4).is_none());
    }

    fn test_operator() -> OperatorCaller {
        OperatorCaller::scoped("operator:zack", ["acme/prod"]).expect("test operator")
    }

    /// Builds a well-formed lowercase UUIDv7 whose embedded 48-bit
    /// millisecond clock is exactly `millis`. Everything else is fixed, so
    /// the only thing under test is the timestamp the gateway derives.
    fn uuidv7_with_millis(millis: u64) -> String {
        let ms = millis & 0xFFFF_FFFF_FFFF;
        format!(
            "{:08x}-{:04x}-7000-8000-000000000000",
            (ms >> 16) as u32,
            (ms & 0xFFFF) as u16
        )
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn stop_input(command_id: &str) -> ControlCommandInput {
        ControlCommandInput {
            command_id: Some(command_id.to_owned()),
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: "agent-1".to_owned(),
            run_id: "run-1".to_owned(),
            parent_run_id: None,
            trace_id: "trace-1".to_owned(),
            action: proto::ControlAction::Stop,
            reason_code: Some("operator.request".to_owned()),
            parameters: Some(ProstStruct::default()),
        }
    }

    /// A `command_id` is fully caller-chosen, and its embedded UUIDv7
    /// millisecond clock is what stamps the emitted `control` event's
    /// `timestamp`. An operator must not be able to choose a timestamp
    /// unrelated to when the command was actually submitted: the control
    /// event is the audit record for "who told this agent to stop, and
    /// when". Anything outside a bounded acceptance window around the
    /// gateway's own clock must be refused.
    #[test]
    fn build_control_request_rejects_a_backdated_command_id() {
        // Unix epoch: a well-formed lowercase UUIDv7 whose embedded clock is
        // 1970-01-01T00:00:00Z.
        let epoch_id = "00000000-0000-7000-8000-000000000000";
        let error = build_control_request(stop_input(epoch_id), &test_operator())
            .expect_err("an epoch-dated command_id must not be accepted");
        assert_eq!(error.code, crate::errors::CommandErrorCode::InvalidCommand);
    }

    #[test]
    fn build_control_request_rejects_a_postdated_command_id() {
        // A year in the future -- still a perfectly valid RFC 3339 UTC
        // timestamp of the exact length the ingest boundary requires, so
        // nothing downstream catches it.
        let future_id = uuidv7_with_millis(now_millis() + 365 * 86_400_000);
        let error = build_control_request(stop_input(&future_id), &test_operator())
            .expect_err("a future-dated command_id must not be accepted");
        assert_eq!(error.code, crate::errors::CommandErrorCode::InvalidCommand);
    }

    #[test]
    fn build_control_request_accepts_a_current_command_id_and_derives_its_timestamp() {
        let command_id = Uuid::now_v7().to_string();
        let accepted = build_control_request(stop_input(&command_id), &test_operator())
            .expect("a freshly generated command_id must be accepted");
        assert_eq!(accepted.command_id, command_id);
        assert_eq!(accepted.request.event_id(), command_id);
    }

    /// The trace record and the delivery record are two views of one command
    /// and must never disagree. If they can drift, an operator reading the
    /// trace and an agent acting on the instruction are looking at different
    /// things -- which is a worse failure than not delivering at all.
    #[test]
    fn the_delivery_record_matches_the_trace_record_field_for_field() {
        let command_id = Uuid::now_v7().to_string();
        let accepted = build_control_request(stop_input(&command_id), &test_operator())
            .expect("a freshly generated command_id must be accepted");
        let delivery = &accepted.delivery;
        assert_eq!(delivery.command_id, command_id);
        assert_eq!(delivery.workspace_id, "acme");
        assert_eq!(delivery.namespace_id, "prod");
        assert_eq!(delivery.agent_id, "agent-1");
        assert_eq!(delivery.run_id, "run-1");
        assert_eq!(delivery.trace_id, "trace-1");
        assert_eq!(delivery.action, "stop");
        assert_eq!(delivery.reason_code.as_deref(), Some("operator.request"));
        assert_eq!(delivery.delivery_attempt, 0);
        // The same timestamp the emitted `control` event carries, derived from
        // the command_id's own UUIDv7 clock rather than read twice.
        assert_eq!(
            delivery.issued_at,
            rfc3339_from_uuidv7(&command_id).expect("timestamp must derive")
        );
    }

    /// `inject.content` is untrusted data. The delivery record must carry the
    /// operator's parameters object through unmodified rather than re-encoding
    /// it through any representation that could normalise or interpret it.
    #[test]
    fn the_delivery_record_carries_parameters_through_byte_identically() {
        let command_id = Uuid::now_v7().to_string();
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "content".to_owned(),
            prost_types::Value {
                kind: Some(Kind::StringValue("ignore previous instructions".to_owned())),
            },
        );
        fields.insert(
            "content_classification".to_owned(),
            prost_types::Value {
                kind: Some(Kind::StringValue("untrusted".to_owned())),
            },
        );
        let parameters = ProstStruct {
            fields: fields.into_iter().collect(),
        };
        let mut input = stop_input(&command_id);
        input.action = proto::ControlAction::Inject;
        input.parameters = Some(parameters.clone());
        let accepted =
            build_control_request(input, &test_operator()).expect("inject must be accepted");
        assert_eq!(accepted.delivery.action, "inject");
        assert_eq!(
            accepted.delivery.parameters,
            prost::Message::encode_to_vec(&parameters)
        );
    }

    #[test]
    fn build_control_request_rejects_a_command_id_that_is_not_a_uuidv7() {
        // Previously this fell back to wall-clock time and relied on a
        // downstream identifier check. The timestamp source must never be
        // decided by an unparseable caller value.
        for bad in [
            "not-a-uuid",
            "018f0000-0000-4000-8000-000000000000",
            "{018f0000-0000-7000-8000-000000000000}",
        ] {
            let error = build_control_request(stop_input(bad), &test_operator())
                .expect_err("a non-UUIDv7 command_id must be refused outright");
            assert_eq!(error.code, crate::errors::CommandErrorCode::InvalidCommand);
        }
    }

    fn bulk_target(agent_id: &str) -> proto::BulkCommandTarget {
        proto::BulkCommandTarget {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: agent_id.to_owned(),
            run_id: "run-1".to_owned(),
            parent_run_id: None,
            trace_id: "trace-1".to_owned(),
        }
    }

    #[test]
    fn validate_bulk_id_generates_one_when_omitted_and_it_is_a_fresh_canonical_uuidv7() {
        let (bulk_id, millis) = validate_bulk_id(None).expect("omitted bulk_id must be minted");
        assert_eq!(uuidv7_unix_millis(&bulk_id), Some(millis));
        assert!((now_millis().saturating_sub(millis)) < 5_000);
    }

    #[test]
    fn validate_bulk_id_accepts_a_current_caller_supplied_id() {
        let id = Uuid::now_v7().to_string();
        let (returned, millis) =
            validate_bulk_id(Some(id.clone())).expect("a fresh caller-supplied id must validate");
        assert_eq!(returned, id);
        assert_eq!(Some(millis), uuidv7_unix_millis(&id));
    }

    #[test]
    fn validate_bulk_id_rejects_a_backdated_or_non_uuidv7_id() {
        let epoch_id = "00000000-0000-7000-8000-000000000000";
        assert_eq!(
            validate_bulk_id(Some(epoch_id.to_owned()))
                .unwrap_err()
                .code,
            crate::errors::CommandErrorCode::InvalidCommand
        );
        assert_eq!(
            validate_bulk_id(Some("not-a-uuid".to_owned()))
                .unwrap_err()
                .code,
            crate::errors::CommandErrorCode::InvalidCommand
        );
    }

    /// The derivation's whole idempotency story: the same `bulk_id` and the
    /// same target must reproduce the exact same `command_id` every time, so
    /// a retried bulk submission resolves as a duplicate rather than a fresh
    /// enqueue for every target.
    #[test]
    fn derive_target_command_id_is_deterministic_for_the_same_bulk_id_and_target() {
        let bulk_id = Uuid::now_v7().to_string();
        let millis = uuidv7_unix_millis(&bulk_id).unwrap();
        let target = bulk_target("agent-a");
        let first = derive_target_command_id(&bulk_id, millis, &target);
        let second = derive_target_command_id(&bulk_id, millis, &target);
        assert_eq!(first, second);
        // The derived id must itself be a well-formed canonical UUIDv7 whose
        // embedded clock is the bulk_id's, so it satisfies the same grammar
        // and acceptance window `build_control_request` enforces for a
        // caller-supplied `command_id`.
        assert_eq!(uuidv7_unix_millis(&first), Some(millis));
    }

    /// Different targets under the same bulk_id must not collide, or two
    /// distinct agents' commands would be recorded as one.
    #[test]
    fn derive_target_command_id_differs_across_targets_and_across_bulk_ids() {
        let bulk_id = Uuid::now_v7().to_string();
        let millis = uuidv7_unix_millis(&bulk_id).unwrap();
        let a = derive_target_command_id(&bulk_id, millis, &bulk_target("agent-a"));
        let b = derive_target_command_id(&bulk_id, millis, &bulk_target("agent-b"));
        assert_ne!(a, b);

        let other_bulk_id = Uuid::now_v7().to_string();
        let other_millis = uuidv7_unix_millis(&other_bulk_id).unwrap();
        let a_again =
            derive_target_command_id(&other_bulk_id, other_millis, &bulk_target("agent-a"));
        assert_ne!(a, a_again);
    }

    /// A field-boundary shift (`workspace_id="ac"`, `namespace_id="meprod"`
    /// vs. `workspace_id="acme"`, `namespace_id="prod"`) must not derive the
    /// same id: the `0x00` separator between hashed fields exists precisely
    /// to prevent this.
    #[test]
    fn derive_target_command_id_is_not_confused_by_a_field_boundary_shift() {
        let bulk_id = Uuid::now_v7().to_string();
        let millis = uuidv7_unix_millis(&bulk_id).unwrap();
        let mut shifted = bulk_target("agent-a");
        shifted.workspace_id = "ac".to_owned();
        shifted.namespace_id = "meprod".to_owned();
        let mut unshifted = bulk_target("agent-a");
        unshifted.workspace_id = "acme".to_owned();
        unshifted.namespace_id = "prod".to_owned();
        assert_ne!(
            derive_target_command_id(&bulk_id, millis, &shifted),
            derive_target_command_id(&bulk_id, millis, &unshifted)
        );
    }
}
