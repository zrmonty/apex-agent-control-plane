use std::collections::HashSet;

use prost::Message;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES, proto};

const MAX_STRUCT_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub(crate) authenticated: bool,
    pub(crate) allowed_scopes: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestRequest {
    pub(crate) event_id: String,
    pub(crate) workspace_id: String,
    pub(crate) namespace_id: String,
    pub(crate) scope_key: String,
    pub(crate) envelope: Vec<u8>,
}

impl IngestRequest {
    #[cfg(feature = "test-support")]
    pub fn new(
        event_id: impl Into<String>,
        workspace_id: impl Into<String>,
        namespace_id: impl Into<String>,
        envelope: Vec<u8>,
    ) -> Self {
        let event_id = event_id.into();
        let workspace_id = workspace_id.into();
        let namespace_id = namespace_id.into();
        Self {
            event_id,
            workspace_id: workspace_id.clone(),
            namespace_id: namespace_id.clone(),
            scope_key: format!("{workspace_id}/{namespace_id}"),
            envelope,
        }
    }

    #[cfg(feature = "test-support")]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    #[cfg(feature = "test-support")]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    #[cfg(feature = "test-support")]
    pub fn canonical_hash_for_test(
        envelope: &proto::EventEnvelope,
    ) -> Result<String, GatewayError> {
        canonical_event_hash(envelope)
    }

    pub(crate) fn scope_key(&self) -> &str {
        &self.scope_key
    }

    pub(crate) fn from_validated_transport(
        envelope: proto::EventEnvelope,
    ) -> Result<Self, GatewayError> {
        if envelope.encoded_len() > MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        if !is_lowercase_uuidv7(&envelope.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if !is_rfc3339_utc(&envelope.timestamp) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidTimestamp));
        }
        let integrity = envelope
            .integrity
            .as_ref()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidIntegrity))?;
        if !is_lowercase_sha256(&integrity.event_hash)
            || integrity
                .prev_hash
                .as_deref()
                .is_some_and(|hash| !is_lowercase_sha256(hash))
        {
            return Err(GatewayError::new(GatewayErrorCode::InvalidIntegrity));
        }
        if envelope.r#type == 9 {
            validate_control_data(
                envelope
                    .data
                    .as_ref()
                    .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?,
            )?;
        }
        if canonical_event_hash(&envelope)? != integrity.event_hash {
            return Err(GatewayError::new(GatewayErrorCode::InvalidIntegrity));
        }
        let scope = envelope
            .scope
            .as_ref()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
        if envelope.schema_version != 1
            || !matches!(envelope.r#type, 1..=12)
            || !matches!(
                envelope.actor.as_ref().map(|actor| actor.r#type),
                Some(1..=4)
            )
            || envelope.data.is_none()
            || !is_scope_identifier(&envelope.agent_id)
            || !is_scope_identifier(&envelope.run_id)
            || !is_scope_identifier(&envelope.trace_id)
            || envelope
                .parent_run_id
                .as_deref()
                .is_some_and(|id| !is_scope_identifier(id))
            || !is_scope_identifier(&scope.workspace_id)
            || !is_scope_identifier(&scope.namespace_id)
            || scope.agent_group_ids.len() > 128
            || scope
                .agent_group_ids
                .iter()
                .any(|id| !is_scope_identifier(id))
            || envelope
                .actor
                .as_ref()
                .is_none_or(|actor| !is_scope_identifier(&actor.id))
            || envelope.version.as_ref().is_none_or(|version| {
                !is_scope_identifier(&version.agent_code)
                    || !is_scope_identifier(&version.prompt)
                    || !is_scope_identifier(&version.model)
            })
        {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        let serialized = envelope.encode_to_vec();
        Ok(Self {
            event_id: envelope.event_id,
            workspace_id: scope.workspace_id.clone(),
            namespace_id: scope.namespace_id.clone(),
            scope_key: format!("{}/{}", scope.workspace_id, scope.namespace_id),
            envelope: serialized,
        })
    }
}

fn validate_control_data(data: &prost_types::Struct) -> Result<(), GatewayError> {
    let value = prost_struct_to_json(data)?;
    let object = value
        .as_object()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    let required = ["action", "enforcement", "reason_code", "parameters"];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    if !matches!(
        action,
        "stop" | "pause" | "resume" | "inject" | "set_budget"
    ) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    if object.get("enforcement").and_then(Value::as_str) != Some("cooperative") {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    if let Some(reason_code) = object.get("reason_code")
        && !reason_code.is_null()
        && !reason_code.as_str().is_some_and(is_scope_identifier)
    {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let parameters = object
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    match action {
        "stop" | "pause" | "resume" if !parameters.is_empty() => {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        "inject"
            if parameters.len() != 2
                || !matches!(parameters.get("content").and_then(Value::as_str), Some(content) if !content.is_empty() && content.len() <= 32 * 1024)
                || parameters
                    .get("content_classification")
                    .and_then(Value::as_str)
                    != Some("untrusted") =>
        {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        "set_budget" => {
            let budget_kind = parameters.get("budget_kind").and_then(Value::as_str);
            let limit = parameters.get("limit").and_then(Value::as_f64);
            if parameters.len() != 2
                || !matches!(budget_kind, Some("tokens" | "cost"))
                || !limit.is_some_and(|value| value.is_finite() && value > 0.0)
            {
                return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_event_hash(envelope: &proto::EventEnvelope) -> Result<String, GatewayError> {
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

fn prost_struct_to_json(value: &prost_types::Struct) -> Result<Value, GatewayError> {
    prost_struct_to_json_at_depth(value, 0)
}

fn prost_struct_to_json_at_depth(
    value: &prost_types::Struct,
    depth: usize,
) -> Result<Value, GatewayError> {
    if depth > MAX_STRUCT_DEPTH {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let mut object = Map::new();
    for (key, value) in &value.fields {
        object.insert(key.clone(), prost_value_to_json_at_depth(value, depth + 1)?);
    }
    Ok(Value::Object(object))
}

fn prost_value_to_json_at_depth(
    value: &prost_types::Value,
    depth: usize,
) -> Result<Value, GatewayError> {
    if depth > MAX_STRUCT_DEPTH {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NullValue(_)) => Ok(Value::Null),
        Some(prost_types::value::Kind::NumberValue(number)) => Number::from_f64(*number)
            .map(Value::Number)
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure)),
        Some(prost_types::value::Kind::StringValue(string)) => Ok(Value::String(string.clone())),
        Some(prost_types::value::Kind::BoolValue(boolean)) => Ok(Value::Bool(*boolean)),
        Some(prost_types::value::Kind::StructValue(object)) => {
            prost_struct_to_json_at_depth(object, depth + 1)
        }
        Some(prost_types::value::Kind::ListValue(list)) => Ok(Value::Array(
            list.values
                .iter()
                .map(|value| prost_value_to_json_at_depth(value, depth + 1))
                .collect::<Result<_, _>>()?,
        )),
        None => Err(GatewayError::new(GatewayErrorCode::InvalidStructure)),
    }
}

fn event_type_name(value: i32) -> Option<&'static str> {
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

fn actor_type_name(value: i32) -> Option<&'static str> {
    Some(match value {
        1 => "user",
        2 => "agent",
        3 => "system",
        4 => "schedule",
        _ => return None,
    })
}

pub(crate) fn is_lowercase_uuidv7(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().get(8) == Some(&b'-')
        && value.as_bytes().get(13) == Some(&b'-')
        && value.as_bytes().get(18) == Some(&b'-')
        && value.as_bytes().get(23) == Some(&b'-')
        && value.as_bytes().get(14) == Some(&b'7')
        && matches!(value.as_bytes().get(19), Some(b'8' | b'9' | b'a' | b'b'))
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 27
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[26] != b'Z'
    {
        return false;
    }
    if !bytes[..4]
        .iter()
        .chain(&bytes[5..7])
        .chain(&bytes[8..10])
        .chain(&bytes[11..13])
        .chain(&bytes[14..16])
        .chain(&bytes[17..19])
        .chain(&bytes[20..26])
        .all(u8::is_ascii_digit)
    {
        return false;
    }
    let month = two_digits(&bytes[5..7]);
    let day = two_digits(&bytes[8..10]);
    let hour = two_digits(&bytes[11..13]);
    let minute = two_digits(&bytes[14..16]);
    let second = two_digits(&bytes[17..19]);
    let year = four_digits(&bytes[..4]);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    };
    (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn two_digits(value: &[u8]) -> u32 {
    u32::from(value[0] - b'0') * 10 + u32::from(value[1] - b'0')
}

fn four_digits(value: &[u8]) -> u32 {
    u32::from(value[0] - b'0') * 1_000
        + u32::from(value[1] - b'0') * 100
        + u32::from(value[2] - b'0') * 10
        + u32::from(value[3] - b'0')
}

pub(crate) fn is_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "018f5c91-2d88-7c00-8000-000000000001";

    fn value(kind: prost_types::value::Kind) -> prost_types::Value {
        prost_types::Value { kind: Some(kind) }
    }

    fn envelope() -> proto::EventEnvelope {
        proto::EventEnvelope {
            event_id: EVENT.to_owned(),
            timestamp: "2024-02-29T23:59:59.000000Z".to_owned(),
            r#type: 1,
            agent_id: "agent".to_owned(),
            run_id: "run".to_owned(),
            parent_run_id: None,
            trace_id: "trace".to_owned(),
            scope: Some(proto::Scope {
                workspace_id: "workspace".to_owned(),
                namespace_id: "namespace".to_owned(),
                agent_group_ids: vec![],
            }),
            actor: Some(proto::Actor {
                r#type: 2,
                id: "agent".to_owned(),
            }),
            version: Some(proto::Version {
                agent_code: "code".to_owned(),
                prompt: "prompt".to_owned(),
                model: "model".to_owned(),
            }),
            data: Some(prost_types::Struct::default()),
            integrity: Some(proto::Integrity {
                prev_hash: None,
                event_hash: String::new(),
            }),
            schema_version: 1,
        }
    }

    fn control(action: &str, parameters: Map<String, Value>) -> prost_types::Struct {
        let mut fields = Map::new();
        fields.insert("action".to_owned(), Value::String(action.to_owned()));
        fields.insert(
            "enforcement".to_owned(),
            Value::String("cooperative".to_owned()),
        );
        fields.insert("reason_code".to_owned(), Value::Null);
        fields.insert("parameters".to_owned(), Value::Object(parameters));
        json_to_struct(&Value::Object(fields))
    }

    fn json_to_struct(value: &Value) -> prost_types::Struct {
        let Value::Object(fields) = value else {
            panic!("object expected")
        };
        prost_types::Struct {
            fields: fields
                .iter()
                .map(|(key, value)| (key.clone(), json_to_value(value)))
                .collect(),
        }
    }

    fn json_to_value(value: &Value) -> prost_types::Value {
        let kind = match value {
            Value::Null => prost_types::value::Kind::NullValue(0),
            Value::Bool(value) => prost_types::value::Kind::BoolValue(*value),
            Value::Number(value) => prost_types::value::Kind::NumberValue(value.as_f64().unwrap()),
            Value::String(value) => prost_types::value::Kind::StringValue(value.clone()),
            Value::Array(values) => prost_types::value::Kind::ListValue(prost_types::ListValue {
                values: values.iter().map(json_to_value).collect(),
            }),
            Value::Object(_) => prost_types::value::Kind::StructValue(json_to_struct(value)),
        };
        prost_types::Value { kind: Some(kind) }
    }

    #[test]
    fn primitive_validators_cover_boundary_cases() {
        assert!(is_lowercase_uuidv7(EVENT));
        assert!(!is_lowercase_uuidv7("bad"));
        assert!(!is_lowercase_uuidv7("018f5c91-2d88-7c00-c000-000000000001"));
        assert!(is_lowercase_sha256(&"a".repeat(64)));
        assert!(!is_lowercase_sha256(&"A".repeat(64)));
        assert!(is_rfc3339_utc("2024-02-29T23:59:59.000000Z"));
        assert!(!is_rfc3339_utc("2023-02-29T23:59:59.000000Z"));
        assert!(!is_rfc3339_utc("2024-13-01T00:00:00.000000Z"));
        assert!(is_scope_identifier("a.b_c:d-1"));
        assert!(!is_scope_identifier(""));
        assert!(!is_scope_identifier("bad value"));
    }

    #[test]
    fn converts_all_protobuf_value_kinds_and_rejects_missing_kind() {
        for kind in [
            prost_types::value::Kind::NullValue(0),
            prost_types::value::Kind::NumberValue(1.5),
            prost_types::value::Kind::StringValue("text".to_owned()),
            prost_types::value::Kind::BoolValue(true),
            prost_types::value::Kind::StructValue(prost_types::Struct::default()),
            prost_types::value::Kind::ListValue(prost_types::ListValue { values: vec![] }),
        ] {
            assert!(prost_value_to_json_at_depth(&value(kind), 0).is_ok());
        }
        assert!(prost_value_to_json_at_depth(&prost_types::Value { kind: None }, 0).is_err());
        assert!(
            prost_value_to_json_at_depth(
                &value(prost_types::value::Kind::NullValue(0)),
                MAX_STRUCT_DEPTH + 1
            )
            .is_err()
        );
    }

    #[test]
    fn control_validation_accepts_safe_actions_and_rejects_unsafe_shapes() {
        for action in ["stop", "pause", "resume"] {
            assert!(validate_control_data(&control(action, Map::new())).is_ok());
        }
        let mut inject = Map::new();
        inject.insert("content".to_owned(), Value::String("untrusted".to_owned()));
        inject.insert(
            "content_classification".to_owned(),
            Value::String("untrusted".to_owned()),
        );
        assert!(validate_control_data(&control("inject", inject)).is_ok());
        let mut budget = Map::new();
        budget.insert("budget_kind".to_owned(), Value::String("tokens".to_owned()));
        budget.insert(
            "limit".to_owned(),
            Value::Number(Number::from_f64(1.0).unwrap()),
        );
        assert!(validate_control_data(&control("set_budget", budget)).is_ok());
        assert!(validate_control_data(&control("unknown", Map::new())).is_err());
        let mut bad_inject = Map::new();
        bad_inject.insert("content".to_owned(), Value::String(String::new()));
        assert!(validate_control_data(&control("inject", bad_inject)).is_err());
        let mut bad_budget = Map::new();
        bad_budget.insert("budget_kind".to_owned(), Value::String("tokens".to_owned()));
        bad_budget.insert(
            "limit".to_owned(),
            Value::Number(Number::from_f64(-1.0).unwrap()),
        );
        assert!(validate_control_data(&control("set_budget", bad_budget)).is_err());
    }

    #[test]
    fn canonical_hash_and_transport_validation_cover_missing_and_invalid_fields() {
        let mut valid = envelope();
        valid.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&valid).unwrap();
        assert!(canonical_event_hash(&valid).is_ok());
        assert!(IngestRequest::from_validated_transport(valid.clone()).is_ok());
        let mut missing = valid.clone();
        missing.scope = None;
        assert!(canonical_event_hash(&missing).is_err());
        let mut invalid = valid;
        invalid.schema_version = 2;
        invalid.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&invalid).unwrap();
        assert_eq!(
            IngestRequest::from_validated_transport(invalid)
                .unwrap_err()
                .code,
            GatewayErrorCode::InvalidStructure
        );
        assert_eq!(event_type_name(99), None);
        assert_eq!(actor_type_name(99), None);
    }
}
