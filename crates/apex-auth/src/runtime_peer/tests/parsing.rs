use super::*;

#[test]
fn valid_policy_accepts_exact_controller_and_agent_roles() {
    for role in ["controller", "agent"] {
        let mut input = document();
        input["peers"][0]["role"] = json!(role);
        assert_eq!(parse(&input).unwrap().version(), "policy-1");
    }
}

#[test]
fn snapshot_owns_original_bytes_without_retaining_raw_policy_debug() {
    let mut input = document();
    input["version"] = json!("policy-canary-do-not-log");
    let mut bytes = serde_json::to_vec(&input).unwrap();
    let policy = RuntimePeerPolicy::parse_json(&bytes).unwrap();
    bytes.fill(b'x');
    assert_eq!(policy.version(), "policy-canary-do-not-log");
    assert_eq!(format!("{policy:?}"), "RuntimePeerPolicy { [redacted] }");
}

#[test]
fn decoded_duplicate_field_names_reject_at_every_object_level() {
    let encoded = serde_json::to_string(&document()).unwrap();
    for (needle, duplicate) in [
        (
            r#""schemaVersion":1"#,
            r#""schemaVersion":1,"schema\u0056ersion":1"#,
        ),
        (
            r#""version":"policy-1""#,
            r#""version":"policy-1","ver\u0073ion":"policy-1""#,
        ),
        (
            r#""role":"controller""#,
            r#""role":"controller","r\u006fle":"controller""#,
        ),
        (r#""revoked":false"#, r#""revoked":false,"revoked":false"#),
        (
            r#""workspaceId":"work""#,
            r#""workspaceId":"work","workspace\u0049d":"work""#,
        ),
    ] {
        assert!(encoded.contains(needle));
        let bytes = encoded.replacen(needle, duplicate, 1);
        assert_eq!(
            RuntimePeerPolicy::parse_json(bytes.as_bytes()).unwrap_err(),
            RuntimePeerError::InvalidPolicy
        );
    }
}

#[test]
fn escaped_unique_field_name_is_not_itself_ambiguous() {
    let encoded = serde_json::to_string(&document())
        .unwrap()
        .replace("\"version\"", "\"ver\\u0073ion\"");
    assert_eq!(
        RuntimePeerPolicy::parse_json(encoded.as_bytes())
            .unwrap()
            .version(),
        "policy-1"
    );
}

#[test]
fn unknown_fields_reject_at_every_object_level() {
    for level in 0..3 {
        let mut input = document();
        let object = match level {
            0 => &mut input,
            1 => &mut input["peers"][0],
            _ => &mut input["peers"][0]["grants"][0],
        };
        object["canary-secret-extra"] = json!("never-print-this");
        invalid(&input);
    }
}

#[test]
fn required_fields_cannot_be_omitted_or_null() {
    for (level, fields) in [
        (
            0,
            &[
                "schemaVersion",
                "version",
                "validFromUnixUs",
                "expiresAtUnixUs",
                "peers",
            ][..],
        ),
        (
            1,
            &[
                "certificateSha256",
                "identityId",
                "role",
                "revoked",
                "grants",
            ][..],
        ),
        (2, &["installationId", "workspaceId", "namespaceId"][..]),
    ] {
        for field in fields {
            for null in [false, true] {
                let mut input = document();
                let object = match level {
                    0 => &mut input,
                    1 => &mut input["peers"][0],
                    _ => &mut input["peers"][0]["grants"][0],
                };
                if null {
                    object[*field] = Value::Null;
                } else {
                    object.as_object_mut().unwrap().remove(*field);
                }
                invalid(&input);
            }
        }
    }
}

#[test]
fn positional_struct_arrays_are_not_policy_objects() {
    let mut input = document();
    input["peers"][0]["grants"][0] = json!([INSTALL_A, "work", "ns"]);
    invalid(&input);
    let mut input = document();
    input["peers"][0] = json!([
        "11".repeat(32),
        IDENTITY,
        "controller",
        false,
        [grant(INSTALL_A, "work", "ns")]
    ]);
    invalid(&input);
    let input = document();
    invalid(&json!([
        1,
        "policy-1",
        "1",
        "18446744073709551615",
        input["peers"]
    ]));
}

#[test]
fn schema_role_bool_and_collection_types_are_exact() {
    for value in [json!(0), json!(2), json!(1.0), json!("1"), json!(true)] {
        let mut input = document();
        input["schemaVersion"] = value;
        invalid(&input);
    }
    for value in [
        json!("Controller"),
        json!("operator"),
        json!("workload"),
        json!("*"),
        json!(1),
        json!(false),
    ] {
        let mut input = document();
        input["peers"][0]["role"] = value;
        invalid(&input);
    }
    for value in [json!("false"), json!(0), json!([])] {
        let mut input = document();
        input["peers"][0]["revoked"] = value;
        invalid(&input);
    }
    for value in [json!({}), json!("peers"), json!(false), json!([])] {
        let mut input = document();
        input["peers"] = value;
        invalid(&input);
    }
    let mut input = document();
    input["peers"][0]["grants"] = json!({});
    invalid(&input);
    input["peers"][0]["grants"] = json!([]);
    invalid(&input);
}

#[test]
fn timestamps_are_canonical_u64_decimal_strings_not_json_numbers() {
    for field in ["validFromUnixUs", "expiresAtUnixUs"] {
        for value in [
            json!(1),
            json!(1.0),
            json!("1.0"),
            json!("1e3"),
            json!("+1"),
            json!("-1"),
            json!("01"),
            json!(" 1"),
            json!("1 "),
            json!(""),
            json!("18446744073709551616"),
        ] {
            let mut input = document();
            input[field] = value;
            invalid(&input);
        }
    }
    for (from, until) in [("0", "2"), ("2", "2"), ("3", "2")] {
        let mut input = document();
        input["validFromUnixUs"] = json!(from);
        input["expiresAtUnixUs"] = json!(until);
        invalid(&input);
    }
}

#[test]
fn identifiers_follow_exact_bounded_domain_grammar() {
    for field in ["version", "identityId", "workspaceId", "namespaceId"] {
        for value in [
            "",
            "*",
            "work/ns",
            " a",
            "a ",
            "a..b",
            "a\n",
            "a\0",
            "é",
            "spiffe://runtime/a",
        ] {
            let mut input = document();
            match field {
                "version" => input[field] = json!(value),
                "identityId" => input["peers"][0][field] = json!(value),
                _ => input["peers"][0]["grants"][0][field] = json!(value),
            }
            invalid(&input);
        }
    }
}

#[test]
fn pins_are_exact_lowercase_sha256_without_prefix_or_controls() {
    for pin in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("sha256:{}", "a".repeat(64)),
        format!("{}\n", "a".repeat(63)),
    ] {
        let mut input = document();
        input["peers"][0]["certificateSha256"] = json!(pin);
        invalid(&input);
    }
}

#[test]
fn installation_requires_lowercase_uuidv7_with_rfc4122_variant() {
    for id in [
        INSTALL_A.to_uppercase(),
        INSTALL_A.replace('-', ""),
        format!("{{{INSTALL_A}}}"),
        INSTALL_A.replacen("7d0e", "4d0e", 1),
        INSTALL_A.replacen("8f12", "0f12", 1),
        format!("{INSTALL_A}\n"),
        "*".into(),
    ] {
        let mut input = document();
        input["peers"][0]["grants"][0]["installationId"] = json!(id);
        invalid(&input);
    }
}

#[test]
fn duplicate_pins_and_duplicate_exact_grants_are_rejected() {
    let mut input = document();
    let duplicate = input["peers"][0].clone();
    input["peers"].as_array_mut().unwrap().push(duplicate);
    invalid(&input);
    input["peers"][1]["revoked"] = json!(true);
    invalid(&input);
    let mut input = document();
    input["peers"][0]["grants"] = json!([
        grant(INSTALL_A, "work", "ns"),
        grant(INSTALL_A, "work", "ns")
    ]);
    invalid(&input);
}

#[test]
fn rotation_can_change_revocation_but_not_identity_role_or_grant_set() {
    let mut input = document();
    input["peers"][0]["grants"] = json!([
        grant(INSTALL_A, "work", "ns"),
        grant(INSTALL_B, "other", "space")
    ]);
    let mut rotated = input["peers"][0].clone();
    rotated["certificateSha256"] = json!("22".repeat(32));
    rotated["revoked"] = json!(true);
    rotated["grants"].as_array_mut().unwrap().reverse();
    input["peers"].as_array_mut().unwrap().push(rotated);
    assert!(parse(&input).is_ok());
    let mut changed = input.clone();
    changed["peers"][1]["role"] = json!("agent");
    invalid(&changed);
    let mut changed = input.clone();
    changed["peers"][1]["grants"][0]["namespaceId"] = json!("changed");
    invalid(&changed);
    let mut changed = input;
    changed["peers"][1]["grants"].as_array_mut().unwrap().pop();
    invalid(&changed);
}

#[test]
fn all_parse_diagnostics_are_static_and_have_no_source_chain() {
    use std::error::Error;
    let canary = b"{\"upstream-token-canary\":\"do-not-disclose\"}";
    let error = RuntimePeerPolicy::parse_json(canary).unwrap_err();
    assert_eq!(error.code(), "RUNTIME_PEER_INVALID_POLICY");
    assert_eq!(error.to_string(), "RUNTIME_PEER_INVALID_POLICY");
    assert_eq!(format!("{error:?}"), "RUNTIME_PEER_INVALID_POLICY");
    assert!(error.source().is_none());
}
