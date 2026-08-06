use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::convert::prost_struct_to_json;
use crate::{GatewayError, GatewayErrorCode, proto};

/// Computes the RFC 8785/JCS canonical SHA-256 hash of an event envelope.
///
/// Exposed beyond this crate so independently authenticated writers (for
/// example the OOB control gateway in `apps/control-plane-api`) can construct
/// a validly-hashed `control` envelope without duplicating the canonicalization
/// rules that the ingest admission boundary enforces.
pub fn canonical_event_hash(
    envelope: &proto::EventEnvelope,
) -> Result<String, GatewayError> {
    let scope = envelope
        .scope
        .as_ref()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    let actor = envelope
        .actor
        .as_ref()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    let version = envelope
        .version
        .as_ref()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    let integrity = envelope
        .integrity
        .as_ref()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidIntegrity))?;
    let data = envelope
        .data
        .as_ref()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;

    let mut root = Map::new();
    root.insert(
        "event_id".to_owned(),
        Value::String(envelope.event_id.clone()),
    );
    root.insert(
        "timestamp".to_owned(),
        Value::String(envelope.timestamp.clone()),
    );
    root.insert(
        "type".to_owned(),
        Value::String(
            event_type_name(envelope.r#type)
                .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?
                .to_owned(),
        ),
    );
    root.insert(
        "agent_id".to_owned(),
        Value::String(envelope.agent_id.clone()),
    );
    root.insert("run_id".to_owned(), Value::String(envelope.run_id.clone()));
    root.insert(
        "parent_run_id".to_owned(),
        envelope
            .parent_run_id
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.clone())),
    );
    root.insert(
        "trace_id".to_owned(),
        Value::String(envelope.trace_id.clone()),
    );
    root.insert("scope".to_owned(), {
        let mut value = Map::new();
        value.insert(
            "workspace_id".to_owned(),
            Value::String(scope.workspace_id.clone()),
        );
        value.insert(
            "namespace_id".to_owned(),
            Value::String(scope.namespace_id.clone()),
        );
        value.insert(
            "agent_group_ids".to_owned(),
            Value::Array(
                scope
                    .agent_group_ids
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        Value::Object(value)
    });
    root.insert("actor".to_owned(), {
        let mut value = Map::new();
        value.insert(
            "type".to_owned(),
            Value::String(
                actor_type_name(actor.r#type)
                    .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?
                    .to_owned(),
            ),
        );
        value.insert("id".to_owned(), Value::String(actor.id.clone()));
        Value::Object(value)
    });
    root.insert("version".to_owned(), {
        let mut value = Map::new();
        value.insert(
            "agent_code".to_owned(),
            Value::String(version.agent_code.clone()),
        );
        value.insert("prompt".to_owned(), Value::String(version.prompt.clone()));
        value.insert("model".to_owned(), Value::String(version.model.clone()));
        Value::Object(value)
    });
    root.insert("data".to_owned(), prost_struct_to_json(data)?);
    root.insert("integrity".to_owned(), {
        let mut value = Map::new();
        value.insert(
            "prev_hash".to_owned(),
            integrity
                .prev_hash
                .as_ref()
                .map_or(Value::Null, |hash| Value::String(hash.clone())),
        );
        Value::Object(value)
    });
    root.insert(
        "schema_version".to_owned(),
        Value::from(envelope.schema_version),
    );

    let canonical = serde_jcs::to_vec(&Value::Object(root))
        .map_err(|_| GatewayError::new(GatewayErrorCode::InvalidIntegrity))?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

pub(crate) fn event_type_name(value: i32) -> Option<&'static str> {
    Some(match value {
        1 => "turn_start",
        2 => "llm",
        3 => "tool",
        4 => "message",
        5 => "memory",
        6 => "decision",
        7 => "workflow",
        8 => "agent_spawn",
        9 => "control",
        10 => "score",
        11 => "turn_end",
        12 => "error",
        _ => return None,
    })
}

pub(crate) fn actor_type_name(value: i32) -> Option<&'static str> {
    Some(match value {
        1 => "user",
        2 => "agent",
        3 => "system",
        4 => "schedule",
        _ => return None,
    })
}
