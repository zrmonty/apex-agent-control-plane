//! Generated-wire preservation only, not authenticated/configured readiness.
use super::support::*;
use apex_proxy_runtime_agent::{FILE_DESCRIPTOR_SET, check_runtime_target, proto};
use prost::{Message, Name};
use serde_json::{Value, json};

fn target_json() -> Value {
    json!({"workspaceId": "acme", "namespaceId": "prod", "proxyId": PROXY,
        "revisionId": REVISION, "generation": "9007199254740993", "fencingToken": "18446744073709551615"})
}

fn timing_json() -> Value {
    json!({"name": "inspect", "startedAtUnixUs": "9007199254740993", "durationUs": "18446744073709551615",
        "durationNs": "9007199254740993", "otelTraceId": "0123456789abcdef0123456789abcdef",
        "spanId": "0123456789abcdef", "parentSpanId": "fedcba9876543210", "processInstanceId": INSTANCE,
        "clockSource": "monotonic", "clockResolutionNs": "9007199254740993", "clockUncertaintyUs": "0"})
}

fn round_trip<T>(golden: Value) -> T
where
    T: Message
        + Default
        + PartialEq
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    let value: T = serde_json::from_value(golden.clone()).expect("generated ProtoJSON");
    assert_eq!(serde_json::to_value(&value).unwrap(), golden);
    assert_eq!(T::decode(value.encode_to_vec().as_slice()).unwrap(), value);
    value
}

#[test]
fn separately_generated_target_preserves_every_field_and_hand_encoded_bigints() {
    let value: proto::RuntimeTarget = round_trip(target_json());
    assert_eq!(value, target());
    assert_eq!(
        <proto::RuntimeTarget as Name>::full_name(),
        "apex.v1.RuntimeTarget"
    );
    // Independent literal protobuf tags/lengths and varints (not another encoder).
    let mut binary = vec![
        10, 4, b'a', b'c', b'm', b'e', 18, 4, b'p', b'r', b'o', b'd', 26, 36,
    ];
    binary.extend_from_slice(PROXY.as_bytes());
    binary.extend_from_slice(&[34, 36]);
    binary.extend_from_slice(REVISION.as_bytes());
    binary.extend_from_slice(&[
        40, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10, 48, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x01,
    ]);
    assert_eq!(value.encode_to_vec(), binary);
    assert_eq!(
        proto::RuntimeTarget::decode(binary.as_slice()).unwrap(),
        target()
    );
}

#[test]
fn full_canonical_configuration_uses_agent_generated_protojson_without_app_dependency() {
    let config = configuration();
    assert_eq!(
        proto::RuntimeConfiguration::decode(config.encode_to_vec().as_slice()).unwrap(),
        config
    );
    let value = serde_json::to_value(&config).unwrap();
    assert_eq!(value["generation"], "9007199254740993");
    assert_eq!(value["memoryBytes"], "268435456");
    assert_eq!(value["telemetry"]["maxExportQueueBytes"], "8388608");
    assert_eq!(
        serde_json::from_value::<proto::RuntimeConfiguration>(value).unwrap(),
        config
    );
}

#[test]
fn additive_launch_health_material_and_authority_profile_fields_survive_both_codecs() {
    let golden = json!({"schemaVersion": 1, "target": target_json(), "configHash": "a".repeat(64),
        "runtimeManifestHash": "b".repeat(64), "imageRef": configuration().image_ref,
        "processInstanceId": INSTANCE, "health": {"port": 8081, "credentialRef": "secret://lab/health"},
        "materials": [{"role": "RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN", "reference": "secret://lab/health", "version": "v1"},
            {"role": "RUNTIME_MATERIAL_ROLE_GOVERNANCE_CA", "reference": "secret://lab/governance-ca", "version": "v2"}],
        "launchContextHash": "c".repeat(64), "authorityProfileRef": "authority://lab/private",
        "authorityProfileVersion": "v3"});
    let launch: proto::RuntimeLaunchContext = round_trip(golden);
    assert_eq!(launch.target.unwrap().fencing_token, u64::MAX);
    assert_eq!(launch.health.unwrap().port, 8081);
    assert_eq!(launch.materials.len(), 2);
    // These are untrusted wire values, not generated launch material or authority.
}

#[test]
fn additive_readiness_observation_and_timing_preserve_all_integer_fields() {
    let report = json!({"live": true, "ready": true, "target": target_json(),
        "observedAtUnixUs": "18446744073709551615", "configHash": "a".repeat(64),
        "runtimeManifestHash": "b".repeat(64), "processInstanceId": INSTANCE,
        "checks": [{"id": "READINESS_CHECK_ID_CONFIG", "status": "READINESS_CHECK_STATUS_PASS", "reason": "READINESS_REASON_OK"}],
        "stages": [timing_json()], "launchContextHash": "c".repeat(64)});
    let value: proto::RuntimeObservation = round_trip(json!({"target": target_json(),
        "runtimeId": "a".repeat(64), "state": "synthetic-wire-only", "ready": true, "admitting": true,
        "activeCalls": "9007199254740993", "observedAtUnixUs": "18446744073709551615", "errorCode": "SYNTHETIC",
        "resourceUrl": "https://proxy.apex.test/mcp", "stages": [timing_json()], "readiness": report}));
    assert_eq!(value.active_calls, BIG);
    assert_eq!(value.observed_at_unix_us, u64::MAX);
    let report = value.readiness.unwrap();
    assert_eq!(report.target.unwrap().generation, BIG);
    assert_eq!(report.stages[0].duration_ns, Some(BIG));
    assert_eq!(report.stages[0].clock_uncertainty_us, Some(0));
    // Preserving caller-supplied booleans does not accept readiness/admission.
}

#[test]
fn drain_timeout_and_probe_observation_keep_uint64_precision() {
    let drain: proto::DrainRuntimeRequest =
        round_trip(json!({"target": target_json(), "timeoutUs": "18446744073709551615"}));
    assert_eq!(drain.timeout_us, u64::MAX);
    let probe: proto::UpstreamProbeObservation = round_trip(json!({"target": target_json(),
        "upstreamId": "portfolio", "connected": true, "errorCode": "SYNTHETIC", "serverIdentity": "lab.example.test",
        "catalogHash": "d".repeat(64), "observedAtUnixUs": "9007199254740993"}));
    assert_eq!(probe.observed_at_unix_us, BIG);
}

#[test]
fn generated_defaults_are_decodable_but_are_not_accepted_runtime_targets() {
    let target: proto::RuntimeTarget = serde_json::from_str("{}").unwrap();
    assert_eq!(target, proto::RuntimeTarget::default());
    assert!(check_runtime_target(&target).is_err());
    let request = proto::EnsureRuntimeRequest::decode(&[][..]).unwrap();
    assert!(request.target.is_none() && request.configuration.is_none());
    assert!(
        serde_json::from_str::<proto::RuntimeTarget>(r#"{"generation":"1","generation":"2"}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<proto::RuntimeTarget>(r#"{"unknown":true}"#).is_err());
}

#[test]
fn descriptor_retains_canonical_runtime_methods_and_additive_field_numbers() {
    let set = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let runtime = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("apex/v1/proxy_runtime.proto"))
        .unwrap();
    assert_eq!(runtime.package.as_deref(), Some("apex.v1"));
    let service = runtime
        .service
        .iter()
        .find(|value| value.name.as_deref() == Some("ProxyRuntimeAgent"))
        .unwrap();
    let names: Vec<_> = service
        .method
        .iter()
        .map(|method| method.name.as_deref().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "EnsureRuntime",
            "InspectRuntime",
            "SetAdmission",
            "DrainRuntime",
            "RemoveRuntime",
            "ProbeUpstream"
        ]
    );
    for (message, field, number) in [
        ("RuntimeTarget", "fencing_token", 6),
        ("RuntimeObservation", "readiness", 11),
        ("RuntimeLaunchContext", "launch_context_hash", 9),
        ("RuntimeLaunchContext", "authority_profile_version", 11),
        ("ReadinessReport", "launch_context_hash", 10),
        ("RuntimeHealthBinding", "credential_ref", 2),
    ] {
        let message = runtime
            .message_type
            .iter()
            .find(|value| value.name.as_deref() == Some(message))
            .unwrap();
        let field = message
            .field
            .iter()
            .find(|value| value.name.as_deref() == Some(field))
            .unwrap();
        assert_eq!(field.number, Some(number));
    }
}
