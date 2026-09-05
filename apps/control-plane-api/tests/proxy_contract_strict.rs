use apex_control_plane_api::contract_json::decode_management_json;
use apex_control_plane_api::proto::{
    ProxyActivitySummary, ProxyStageTiming, ProxyTraceSummary, RuntimeConfiguration, RuntimeTarget,
};
use serde_json::json;

#[test]
fn null_first_duplicate_keys_and_aliases_are_rejected() {
    for input in [
        r#"{"durationNs":null,"durationNs":"7"}"#,
        r#"{"durationNs":null,"duration_ns":"7"}"#,
        r#"{"durationNs":null,"duration\u004es":"7"}"#,
    ] {
        assert!(decode_management_json::<ProxyStageTiming>(input.as_bytes()).is_err());
    }
    assert!(
        decode_management_json::<ProxyActivitySummary>(br#"{"trace":null,"trace":{"stages":[]}}"#)
            .is_err()
    );
    let many = format!(
        "{{{}\"durationNs\":\"7\"}}",
        "\"durationNs\":null,".repeat(8193)
    );
    assert!(decode_management_json::<ProxyStageTiming>(many.as_bytes()).is_err());
}

#[test]
fn governance_mode_cannot_be_omitted() {
    assert!(
        decode_management_json::<apex_control_plane_api::proto::McpProxyGovernanceBinding>(b"{}")
            .is_err()
    );
}

#[test]
fn canonical_integer_strings_are_required_even_when_numbers_fit() {
    for value in [
        json!(7),
        json!(9007199254740992_u64),
        json!("07"),
        json!("+7"),
        json!("1e3"),
        json!("-1"),
        json!("18446744073709551616"),
        json!(null),
    ] {
        let input = serde_json::to_vec(&json!({"durationUs": value})).unwrap();
        assert!(decode_management_json::<ProxyStageTiming>(&input).is_err());
    }
    for value in ["0", "7", "9007199254740993", "18446744073709551615"] {
        let input = serde_json::to_vec(&json!({"durationUs": value})).unwrap();
        let decoded = decode_management_json::<ProxyStageTiming>(&input).unwrap();
        assert_eq!(decoded.duration_us.to_string(), value);
    }
}

#[test]
fn optional_nested_and_fencing_integers_use_the_same_profile() {
    assert!(decode_management_json::<ProxyStageTiming>(br#"{"durationNs":7}"#).is_err());
    assert!(
        decode_management_json::<RuntimeTarget>(br#"{"generation":"01","fencingToken":"1"}"#)
            .is_err()
    );
    assert!(
        decode_management_json::<ProxyActivitySummary>(
            br#"{"trace":{"stages":[{"durationUs":7}]}}"#
        )
        .is_err()
    );
}

#[test]
fn unknown_duplicate_and_missing_request_identifiers_are_refused() {
    for input in [
        br#"{"durationUs":"7","durationUs":"8"}"#.as_slice(),
        br#"{"durationUs":"7","duration_us":"8"}"#,
        br#"{"surprise":true}"#,
    ] {
        assert!(decode_management_json::<ProxyStageTiming>(input).is_err());
    }
    assert!(
        decode_management_json::<ProxyActivitySummary>(
            br#"{"lifecycle":{"operation":{"requestId":"0191b7f1-7f2c-4c13-9a61-2f29f2be1001"}}}"#
        )
        .is_err()
    );
}

#[test]
fn byte_and_field_limits_apply_before_acceptance() {
    let huge = serde_json::to_vec(&json!({"name":"x".repeat(262145)})).unwrap();
    assert!(decode_management_json::<ProxyStageTiming>(&huge).is_err());
    let wide = serde_json::to_vec(&json!({"missingStages":vec!["stage"; 8193]})).unwrap();
    assert!(decode_management_json::<ProxyTraceSummary>(&wide).is_err());
}

#[test]
fn runtime_resource_audience_and_required_configuration_agree_with_typescript() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    ))
    .unwrap();
    assert!(
        decode_management_json::<RuntimeConfiguration>(&serde_json::to_vec(&fixture).unwrap())
            .is_ok()
    );
    for audience in ["apex-mcp-proxy", "https://portfolio-api.apex.test/mcp", ""] {
        let mut value = fixture.clone();
        value["auth"]["audience"] = json!(audience);
        assert!(
            decode_management_json::<RuntimeConfiguration>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }
    for field in [
        "schemaVersion",
        "resourceUrl",
        "telemetry",
        "spec",
        "generation",
    ] {
        let mut value = fixture.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            decode_management_json::<RuntimeConfiguration>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }
}
