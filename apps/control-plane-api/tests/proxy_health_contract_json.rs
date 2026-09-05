//! Wire regression coverage only: these synthetic messages are not trusted
//! launches, current leases, semantic readiness or admission evidence.
use apex_control_plane_api::{contract_json::decode_management_json, proto};
use prost::Message;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const LARGE: u64 = 9_007_199_254_740_993;

fn round_trip<T>(value: &T) -> Value
where
    T: Message + prost::Name + Default + Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("generated ProtoJSON");
    let decoded: T = decode_management_json(&encoded).expect("strict generated boundary");
    assert_eq!(&decoded, value);
    let binary = value.encode_to_vec();
    assert_eq!(
        &T::decode(binary.as_slice()).expect("generated protobuf"),
        value
    );
    serde_json::from_slice(&encoded).expect("generated JSON tree")
}

fn target() -> proto::RuntimeTarget {
    proto::RuntimeTarget {
        workspace_id: "workspace-a".into(),
        namespace_id: "namespace-a".into(),
        proxy_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001".into(),
        revision_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002".into(),
        generation: LARGE,
        fencing_token: u64::MAX,
    }
}

fn report() -> proto::ReadinessReport {
    proto::ReadinessReport {
        live: true,
        ready: false,
        target: Some(target()),
        observed_at_unix_us: LARGE,
        config_hash: "a".repeat(64),
        runtime_manifest_hash: "b".repeat(64),
        process_instance_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003".into(),
        checks: vec![proto::ReadinessCheck {
            id: proto::ReadinessCheckId::EvidenceAdmission.into(),
            status: proto::ReadinessCheckStatus::Fail.into(),
            reason: proto::ReadinessReason::Unavailable.into(),
        }],
        stages: [1, 7, 999]
            .into_iter()
            .map(|micros| proto::ProxyStageTiming {
                name: "readiness.evidence_admission".into(),
                started_at_unix_us: LARGE,
                duration_us: micros,
                duration_ns: Some(micros * 1_000),
                process_instance_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003".into(),
                clock_source: "injected-wire-fixture".into(),
                clock_resolution_ns: 1,
                clock_uncertainty_us: Some(0),
                ..Default::default()
            })
            .collect(),
        launch_context_hash: "c".repeat(64),
    }
}

#[test]
fn readiness_protojson_and_protobuf_preserve_exact_microseconds_and_presence() {
    let json = round_trip(&report());
    assert_eq!(json["observedAtUnixUs"], LARGE.to_string());
    assert_eq!(json["target"]["generation"], LARGE.to_string());
    assert_eq!(json["target"]["fencingToken"], u64::MAX.to_string());
    for (stage, micros) in json["stages"].as_array().unwrap().iter().zip([1, 7, 999]) {
        assert_eq!(stage["durationUs"], micros.to_string());
        assert_eq!(stage["durationNs"], (micros * 1_000).to_string());
        assert_eq!(stage["startedAtUnixUs"], LARGE.to_string());
        assert_eq!(stage["clockResolutionNs"], "1");
        assert_eq!(stage["clockUncertaintyUs"], "0");
    }
    assert_eq!(
        json["checks"][0]["id"],
        "READINESS_CHECK_ID_EVIDENCE_ADMISSION"
    );
    assert_eq!(json["checks"][0]["status"], "READINESS_CHECK_STATUS_FAIL");
    assert_eq!(json["checks"][0]["reason"], "READINESS_REASON_UNAVAILABLE");
    assert_eq!(json["launchContextHash"], "c".repeat(64));
}

#[test]
fn launch_context_round_trips_separately_from_revision_configuration() {
    let launch = proto::RuntimeLaunchContext {
        schema_version: 1,
        target: Some(target()),
        config_hash: "a".repeat(64),
        runtime_manifest_hash: "b".repeat(64),
        image_ref: format!(
            "registry.example.test/apex/runtime@sha256:{}",
            "d".repeat(64)
        ),
        process_instance_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003".into(),
        health: Some(proto::RuntimeHealthBinding {
            port: 8081,
            credential_ref: "secret://deployment/health".into(),
        }),
        materials: (1..=13)
            .map(|role| proto::RuntimeMaterialBinding {
                role,
                reference: format!("secret://deployment/material-{role}"),
                version: "v1".into(),
            })
            .collect(),
        launch_context_hash: "c".repeat(64),
        authority_profile_ref: "unverified-profile".into(),
        authority_profile_version: "v1".into(),
    };
    let json = round_trip(&launch);
    assert_eq!(json["target"]["fencingToken"], u64::MAX.to_string());
    assert_eq!(json["materials"].as_array().unwrap().len(), 13);
    assert_eq!(json["health"]["port"], 8081);
    assert_eq!(json["authorityProfileRef"], "unverified-profile");
    // This deliberately non-authoritative wire sample has no digest/role-policy
    // claim; strict semantic launch validation must still reject it.
}

#[test]
fn observation_preserves_nested_readiness_without_equating_it_to_admission() {
    let observation = proto::RuntimeObservation {
        target: Some(target()),
        runtime_id: "d".repeat(64),
        state: "Starting".into(),
        ready: false,
        admitting: false,
        active_calls: LARGE,
        observed_at_unix_us: LARGE,
        error_code: "UNAVAILABLE".into(),
        resource_url: "https://proxy.example.test/mcp".into(),
        stages: vec![],
        readiness: Some(report()),
    };
    let json = round_trip(&observation);
    assert_eq!(json["activeCalls"], LARGE.to_string());
    assert_eq!(json["readiness"]["observedAtUnixUs"], LARGE.to_string());
    assert_eq!(json["readiness"]["target"], json["target"]);
    assert!(!observation.ready && !observation.admitting);
    let legacy = proto::RuntimeObservation {
        readiness: None,
        ..observation
    };
    assert!(round_trip(&legacy).get("readiness").is_none());
}

#[test]
fn nested_uint64_fields_require_canonical_decimal_strings() {
    for pointer in [
        "/observedAtUnixUs",
        "/target/generation",
        "/target/fencingToken",
        "/stages/0/startedAtUnixUs",
        "/stages/0/durationUs",
        "/stages/0/durationNs",
        "/stages/0/clockResolutionNs",
        "/stages/0/clockUncertaintyUs",
    ] {
        for invalid in [
            json!(LARGE),
            json!("01"),
            json!("+1"),
            json!("-1"),
            json!("1e3"),
            json!(" 1"),
            json!("18446744073709551616"),
        ] {
            let mut value = serde_json::to_value(report()).unwrap();
            *value.pointer_mut(pointer).unwrap() = invalid;
            assert!(
                decode_management_json::<proto::ReadinessReport>(
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err(),
                "{pointer}"
            );
        }
    }
}

#[test]
fn new_health_messages_reject_unknown_fields_enums_and_original_duplicates() {
    for value in [
        json!({"unknown": true}),
        json!({"target": {"unknown": true}}),
        json!({"checks": [{"unknown": true}]}),
        json!({"checks": [{"id": "READINESS_CHECK_ID_FUTURE"}]}),
        json!({"checks": [{"status": "READINESS_CHECK_STATUS_FUTURE"}]}),
        json!({"checks": [{"reason": "READINESS_REASON_FUTURE"}]}),
    ] {
        assert!(
            decode_management_json::<proto::ReadinessReport>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }
    for input in [
        r#"{"observedAtUnixUs":"1","observedAtUnixUs":"2"}"#,
        r#"{"observedAtUnixUs":"1","observed_at_unix_us":"1"}"#,
        r#"{"target":null,"target":{}}"#,
        r#"{"target":{"generation":"1","generation":"2"}}"#,
        r#"{"checks":[{"id":null,"id":"READINESS_CHECK_ID_CONFIG"}]}"#,
        r#"{"live":true,"\u006cive":true}"#,
    ] {
        assert!(decode_management_json::<proto::ReadinessReport>(input.as_bytes()).is_err());
    }
    assert!(
        decode_management_json::<proto::RuntimeLaunchContext>(br#"{"health":{"host":"0.0.0.0"}}"#)
            .is_err()
    );
    assert!(
        decode_management_json::<proto::RuntimeLaunchContext>(
            br#"{"materials":[{"role":"RUNTIME_MATERIAL_ROLE_FUTURE"}]}"#
        )
        .is_err()
    );
}

#[test]
fn wire_defaults_do_not_supply_semantic_readiness_or_launch_authority() {
    let report: proto::ReadinessReport = decode_management_json(b"{}").unwrap();
    assert!(!report.live && !report.ready);
    assert!(report.target.is_none() && report.checks.is_empty());
    let launch: proto::RuntimeLaunchContext = decode_management_json(b"{}").unwrap();
    assert!(launch.target.is_none() && launch.health.is_none());
    assert_eq!(launch.schema_version, 0);
    // The codec represents messages; readiness/launch owners apply stricter
    // completeness, identity, freshness and policy checks before use.
}
