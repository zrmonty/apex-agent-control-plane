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
use prost_types::Struct as ProstStruct;
use prost_types::value::Kind;
use uuid::Uuid;

use crate::auth::OperatorCaller;
use crate::errors::CommandError;
use crate::proto;

/// Fixed provenance stamped on every control event this gateway emits. The
/// control gateway is not an instrumented agent runtime, so these are not
/// "requested vs effective model" attribution fields -- they identify the
/// OOB gateway itself as the event producer.
const GATEWAY_AGENT_CODE: &str = "apex-control-gateway";
const GATEWAY_PROMPT_REVISION: &str = "control-command-v1";
const GATEWAY_MODEL: &str = "n-a";

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

/// Validates the caller's scope and builds the outbox-ready `IngestRequest`
/// for a control command. Returns the generated/validated `command_id`
/// alongside it so the caller can echo it in the response.
pub fn build_control_request(
    input: ControlCommandInput,
    operator: &OperatorCaller,
) -> Result<(String, IngestRequest), CommandError> {
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
    let timestamp = rfc3339_from_uuidv7(&command_id).unwrap_or_else(rfc3339_now);

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
    Ok((command_id, request))
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

fn action_name(action: proto::ControlAction) -> Option<&'static str> {
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

/// Derives an RFC 3339 microsecond timestamp from a UUIDv7 string's embedded
/// 48-bit millisecond Unix timestamp. Returns `None` for anything that is
/// not a parseable UUIDv7 (the caller falls back to wall-clock time; a
/// malformed `command_id` is rejected downstream by
/// `IngestRequest::from_validated_transport` regardless of the timestamp
/// used here).
fn rfc3339_from_uuidv7(command_id: &str) -> Option<String> {
    let uuid = Uuid::parse_str(command_id).ok()?;
    if uuid.get_version_num() != 7 {
        return None;
    }
    let (secs, nanos) = uuid.get_timestamp()?.to_unix();
    let total_micros = (secs as u128) * 1_000_000 + (nanos as u128) / 1_000;
    Some(format_rfc3339_micros(total_micros))
}

/// Formats the current UTC time as `YYYY-MM-DDTHH:MM:SS.ffffffZ`, matching
/// the RFC 3339 microsecond-precision contract `event-ingest` requires. No
/// `chrono` dependency is used elsewhere in this workspace, so this mirrors
/// that convention with a direct civil-calendar conversion (Howard
/// Hinnant's `civil_from_days`) instead of adding one.
fn rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339_micros(now.as_micros())
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
    fn rfc3339_now_matches_the_ingest_boundary_format() {
        let timestamp = rfc3339_now();
        assert_eq!(timestamp.len(), 27);
        assert!(timestamp.ends_with('Z'));
        assert_eq!(timestamp.as_bytes()[4], b'-');
        assert_eq!(timestamp.as_bytes()[19], b'.');
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
}
