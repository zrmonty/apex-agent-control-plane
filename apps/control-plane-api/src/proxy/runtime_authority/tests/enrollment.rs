use serde_json::{Value, json};

use super::super::RuntimeAuthorityError;
use super::super::enrollment::Enrollment;
use super::support::{bytes, enrollment};

fn rejects(value: &Value) {
    assert!(matches!(
        Enrollment::parse_json(&bytes(value)),
        Err(RuntimeAuthorityError::Unavailable)
    ));
}

#[test]
fn exact_enrollment_parses_without_losing_versions_or_integer_precision() {
    let mut value = enrollment();
    value["validFromUnixUs"] = json!("9007199254740993");
    value["expiresAtUnixUs"] = json!(u64::MAX.to_string());
    let parsed = Enrollment::parse_json(&bytes(&value)).expect("valid component enrollment");
    assert_eq!(parsed.version(), "enrollment-1");
    assert_eq!(parsed.peer_policy_version(), "policy-1");
    assert_eq!(parsed.valid_from_unix_us(), 9_007_199_254_740_993);
    assert_eq!(parsed.expires_at_unix_us(), u64::MAX);
}

#[test]
fn every_enrollment_field_is_mandatory_nonnull_and_unknown_fields_refuse() {
    let original = enrollment();
    for pointer in [
        "",
        "/controllers/0",
        "/installations/0",
        "/installations/0/scopes/0",
    ] {
        let fields: Vec<_> = original
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in fields {
            let mut missing = original.clone();
            missing
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            rejects(&missing);
            let mut null = original.clone();
            null.pointer_mut(pointer).unwrap()[&key] = Value::Null;
            rejects(&null);
        }
        let mut unknown = original.clone();
        unknown.pointer_mut(pointer).unwrap()["unrecognized"] = json!(true);
        rejects(&unknown);
    }
}

#[test]
fn original_json_rejects_decoded_duplicate_names_at_every_object_level() {
    let raw = String::from_utf8(bytes(&enrollment())).unwrap();
    for (key, escaped) in [
        ("version", "ver\\u0073ion"),
        ("workerId", "worker\\u0049d"),
        ("hostPolicyVersion", "hostPolicyVer\\u0073ion"),
        ("namespaceId", "name\\u0073paceId"),
    ] {
        let marker = format!("\"{key}\":");
        let duplicate = raw.replacen(&marker, &format!("\"{escaped}\":null,{marker}"), 1);
        assert_ne!(duplicate.len(), raw.len());
        assert!(Enrollment::parse_json(duplicate.as_bytes()).is_err());
    }
}

#[test]
fn original_json_rejects_trailing_values_invalid_utf8_and_unescaped_controls() {
    let valid = bytes(&enrollment());
    assert!(Enrollment::parse_json(&valid).is_ok());
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b" {}");
    assert!(Enrollment::parse_json(&trailing).is_err());
    let raw_control = String::from_utf8(valid.clone())
        .unwrap()
        .replace("enrollment-1", "enrollment-\0");
    assert!(Enrollment::parse_json(raw_control.as_bytes()).is_err());
    let mut invalid_utf8 = valid;
    invalid_utf8.push(0xff);
    assert!(Enrollment::parse_json(&invalid_utf8).is_err());
    for input in [&b"null"[..], &b"true"[..], &b"[]"[..]] {
        assert!(Enrollment::parse_json(input).is_err());
    }
}

#[test]
fn positional_objects_and_scalar_coercions_are_not_an_alternate_decode_path() {
    for pointer in [
        "",
        "/controllers/0",
        "/installations/0",
        "/installations/0/scopes/0",
    ] {
        let mut value = enrollment();
        let positional = Value::Array(
            value
                .pointer(pointer)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .cloned()
                .collect(),
        );
        *value.pointer_mut(pointer).unwrap() = positional;
        rejects(&value);
    }
    for (pointer, wrong) in [
        ("/schemaVersion", json!("1")),
        ("/schemaVersion", json!(2)),
        ("/version", json!(1)),
        ("/installations/0/revoked", json!("false")),
        ("/controllers", json!({})),
        ("/installations", json!(false)),
        ("/installations/0/scopes", json!({})),
    ] {
        let mut value = enrollment();
        *value.pointer_mut(pointer).unwrap() = wrong;
        rejects(&value);
    }
}

#[test]
fn epoch_grammar_rejects_numbers_overflow_aliases_and_empty_or_reversed_intervals() {
    for bad in [
        json!(100),
        json!(""),
        json!("01"),
        json!("+1"),
        json!("1e2"),
        json!(" 100"),
        json!("100 "),
        json!("18446744073709551616"),
        json!("０"),
    ] {
        for field in ["validFromUnixUs", "expiresAtUnixUs"] {
            let mut value = enrollment();
            value[field] = bad.clone();
            rejects(&value);
        }
    }
    for (from, until) in [("0", "1000"), ("100", "100"), ("1001", "1000")] {
        let mut value = enrollment();
        value["validFromUnixUs"] = json!(from);
        value["expiresAtUnixUs"] = json!(until);
        rejects(&value);
    }
}

#[test]
fn exact_identifier_grammar_rejects_normalization_and_worker_aliases() {
    for pointer in [
        "/version",
        "/peerPolicyVersion",
        "/controllers/0/identityId",
        "/installations/0/agentIdentityId",
        "/installations/0/hostPolicyVersion",
        "/installations/0/scopes/0/workspaceId",
        "/installations/0/scopes/0/namespaceId",
    ] {
        for bad in [
            "",
            " leading",
            "trailing ",
            "a..b",
            "a/b",
            "line\nfeed",
            "nul\0tail",
        ] {
            let mut value = enrollment();
            *value.pointer_mut(pointer).unwrap() = json!(bad);
            rejects(&value);
        }
    }
    for bad in [
        "",
        " leading",
        "trailing ",
        "a/b",
        "line\nfeed",
        "nul\0tail",
        "é",
        "worker@host",
        "worker\\host",
    ] {
        let mut value = enrollment();
        value["controllers"][0]["workerId"] = json!(bad);
        rejects(&value);
    }
}

#[test]
fn lower_rfc_uuid7_is_required_for_installations() {
    for bad in [
        "018F3D4A-8B9C-7D0E-8F12-3A4B5C6D7E01",
        "018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e01",
        "018f3d4a-8b9c-7d0e-0f12-3a4b5c6d7e01",
        "018f3d4a8b9c7d0e8f123a4b5c6d7e01",
    ] {
        let mut value = enrollment();
        value["installations"][0]["installationId"] = json!(bad);
        rejects(&value);
    }
}

#[test]
fn enrollment_debug_does_not_disclose_deployment_metadata() {
    let mut value = enrollment();
    value["controllers"][0]["workerId"] = json!("PRIVATE-WORKER-CANARY");
    let parsed = Enrollment::parse_json(&bytes(&value)).expect("valid component metadata");
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("PRIVATE-WORKER-CANARY"));
    assert!(!debug.contains("controller-a"));
    assert!(debug.len() < 128);
}
