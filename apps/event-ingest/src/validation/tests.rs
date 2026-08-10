use serde_json::{Map, Number, Value};

use super::canonical::{actor_type_name, canonical_event_hash, event_type_name};
use super::control::{MAX_CONTROL_BUDGET_LIMIT, validate_control_data};
use super::convert::{MAX_STRUCT_DEPTH, prost_value_to_json_at_depth};
use super::identifiers::{
    is_lowercase_sha256, is_lowercase_uuidv7, is_rfc3339_utc, is_scope_identifier,
};
use super::secrets::{
    contains_secret_like_control_data, contains_secret_like_data, contains_secret_like_value,
};
use super::*;
use crate::{GatewayErrorCode, proto};

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
    assert!(!is_rfc3339_utc("0000-02-29T23:59:59.000000Z"));
    assert!(!is_rfc3339_utc("2024-13-01T00:00:00.000000Z"));
    assert!(!is_rfc3339_utc("2024-04-31T00:00:00.000000Z")); // 30-day month overflow
    assert!(!is_rfc3339_utc("2024-02-3AT00:00:00.000000Z")); // non-digit
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
    // Depth bound on struct conversion (root depth > MAX rejects before field walk).
    assert!(
        super::convert::prost_struct_to_json_at_depth(
            &prost_types::Struct::default(),
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

    let mut oversized_budget = Map::new();
    oversized_budget.insert("budget_kind".to_owned(), Value::String("tokens".to_owned()));
    oversized_budget.insert(
        "limit".to_owned(),
        Value::Number(Number::from_f64(MAX_CONTROL_BUDGET_LIMIT * 2.0).unwrap()),
    );
    assert!(validate_control_data(&control("set_budget", oversized_budget)).is_err());

    // Non-cooperative enforcement and invalid reason codes fail closed.
    let mut fields = Map::new();
    fields.insert("action".to_owned(), Value::String("stop".to_owned()));
    fields.insert("enforcement".to_owned(), Value::String("hard".to_owned()));
    fields.insert("reason_code".to_owned(), Value::Null);
    fields.insert("parameters".to_owned(), Value::Object(Map::new()));
    assert!(validate_control_data(&json_to_struct(&Value::Object(fields))).is_err());

    let mut reason = Map::new();
    reason.insert("action".to_owned(), Value::String("stop".to_owned()));
    reason.insert(
        "enforcement".to_owned(),
        Value::String("cooperative".to_owned()),
    );
    reason.insert(
        "reason_code".to_owned(),
        Value::String("not a valid scope".to_owned()),
    );
    reason.insert("parameters".to_owned(), Value::Object(Map::new()));
    assert!(validate_control_data(&json_to_struct(&Value::Object(reason))).is_err());

    let mut params = Map::new();
    params.insert("extra".to_owned(), Value::String("x".to_owned()));
    assert!(validate_control_data(&control("stop", params)).is_err());
}

/// `resolve_hold` mirrors `apex_sdk.validation`'s own shape exactly: this
/// server-side check is not optional just because the SDK already checks
/// it client-side -- a client-side check is a courtesy, not a boundary.
#[test]
fn control_validation_enforces_the_resolve_hold_parameter_shape() {
    let mut good = Map::new();
    good.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    good.insert("decision".to_owned(), Value::String("approved".to_owned()));
    good.insert("reason".to_owned(), Value::Null);
    assert!(validate_control_data(&control("resolve_hold", good)).is_ok());

    let mut good_with_reason = Map::new();
    good_with_reason.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    good_with_reason.insert("decision".to_owned(), Value::String("denied".to_owned()));
    good_with_reason.insert(
        "reason".to_owned(),
        Value::String("looked suspicious".to_owned()),
    );
    assert!(validate_control_data(&control("resolve_hold", good_with_reason)).is_ok());

    // Missing the required `reason` key entirely (not even `null`) is refused,
    // same as every other field this validator treats as required.
    let mut missing_reason = Map::new();
    missing_reason.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    missing_reason.insert("decision".to_owned(), Value::String("approved".to_owned()));
    assert!(validate_control_data(&control("resolve_hold", missing_reason)).is_err());

    // hold_token must satisfy the same safe-identifier grammar as a scope
    // component -- it flows back into a `control` event's audit trail.
    let mut bad_token = Map::new();
    bad_token.insert(
        "hold_token".to_owned(),
        Value::String("not a safe token".to_owned()),
    );
    bad_token.insert("decision".to_owned(), Value::String("approved".to_owned()));
    bad_token.insert("reason".to_owned(), Value::Null);
    assert!(validate_control_data(&control("resolve_hold", bad_token)).is_err());

    // decision is a closed vocabulary of exactly two values.
    let mut bad_decision = Map::new();
    bad_decision.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    bad_decision.insert("decision".to_owned(), Value::String("maybe".to_owned()));
    bad_decision.insert("reason".to_owned(), Value::Null);
    assert!(validate_control_data(&control("resolve_hold", bad_decision)).is_err());

    // An empty (but present) reason is refused -- `null` is how "no reason"
    // is spelled, not the empty string.
    let mut empty_reason = Map::new();
    empty_reason.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    empty_reason.insert("decision".to_owned(), Value::String("approved".to_owned()));
    empty_reason.insert("reason".to_owned(), Value::String(String::new()));
    assert!(validate_control_data(&control("resolve_hold", empty_reason)).is_err());

    // Oversized reason (> MAX_HOLD_REASON_BYTES) is refused.
    let mut oversized_reason = Map::new();
    oversized_reason.insert("hold_token".to_owned(), Value::String("hold-1".to_owned()));
    oversized_reason.insert("decision".to_owned(), Value::String("approved".to_owned()));
    oversized_reason.insert(
        "reason".to_owned(),
        Value::String("x".repeat(8 * 1024 + 1)),
    );
    assert!(validate_control_data(&control("resolve_hold", oversized_reason)).is_err());

    // force_stop must never validate under its own name here: its audit
    // event is deliberately recorded as "stop" (see
    // control-plane-api/src/envelope.rs::build_control_request) precisely
    // because this validator predates it and is not the place that gap gets
    // closed by inventing a new accepted literal.
    assert!(validate_control_data(&control("force_stop", Map::new())).is_err());
}

#[test]
fn secret_scanner_detects_high_confidence_shapes_without_hash_field_false_positives() {
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "AKIA1234567890ABCDEF"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "ASIA1234567890ABCDEF"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "AIzaSyA-abcdefghijklmnopqrst"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "ghp_abcdefghijklmnopqrstuvwxyz012345"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "xoxb-123456789012-abcdefgh"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "eyJhbGciOiJIUzI1NiJ9.payload.signature"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "message": "Bearer abcdefghijklmnopqrstuvwxyz012345"
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "nested": [{ "token": "present" }]
    })));
    assert!(contains_secret_like_value(&serde_json::json!({
        "password": "opaque-value"
    })));
    assert!(!contains_secret_like_value(&serde_json::json!({
        "password": null
    })));
    assert!(!contains_secret_like_value(&serde_json::json!({
        "api_key_id": "key-123"
    })));
    assert!(!contains_secret_like_value(&serde_json::json!({
        "password_hash": "deadbeef"
    })));
    // Long hex/base64ish blobs only count outside control-text mode.
    assert!(contains_secret_like_value(&serde_json::json!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )));
    assert!(
        !contains_secret_like_control_data(&prost_types::Struct {
            fields: [(
                "content".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(
                        "ordinary untrusted prose containing the word secret".to_owned(),
                    )),
                },
            )]
            .into_iter()
            .collect(),
        })
        .unwrap()
    );
    assert!(
        contains_secret_like_control_data(&prost_types::Struct {
            fields: [(
                "content".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(
                        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".to_owned(),
                    )),
                },
            )]
            .into_iter()
            .collect(),
        })
        .unwrap()
    );
    assert!(
        contains_secret_like_data(&prost_types::Struct {
            fields: [(
                "password".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("x".to_owned())),
                },
            )]
            .into_iter()
            .collect(),
        })
        .unwrap()
    );
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
    for (code, name) in [
        (1, "turn_start"),
        (2, "llm"),
        (3, "tool"),
        (4, "message"),
        (5, "memory"),
        (6, "decision"),
        (7, "workflow"),
        (8, "agent_spawn"),
        (9, "control"),
        (10, "score"),
        (11, "turn_end"),
        (12, "error"),
    ] {
        assert_eq!(event_type_name(code), Some(name));
    }
    for (code, name) in [(1, "user"), (2, "agent"), (3, "system"), (4, "schedule")] {
        assert_eq!(actor_type_name(code), Some(name));
    }

    // Invalid event id fails closed before hash work.
    let mut bad_id = envelope();
    bad_id.event_id = "not-a-uuid".into();
    assert_eq!(
        IngestRequest::from_validated_transport(bad_id)
            .unwrap_err()
            .code,
        GatewayErrorCode::InvalidEventId
    );
}
