//! Synthetic generated-wire coverage only, not an authenticated lookup, TLS
//! attestation, current lease, execution permit or enforced transport size limit.
use apex_control_plane_api::{contract_json::decode_management_json, proto};
use prost::{Message, Name};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const LARGE: u64 = 9_007_199_254_740_993;
const FIXTURE: &str = include_str!("../../../contracts/fixtures/mcp-proxy/runtime-authority.json");
const DESCRIPTORS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/apex-management.binpb"));

fn fixture(name: &str) -> Value {
    serde_json::from_str::<Value>(FIXTURE).expect("shared wire fixture")[name].clone()
}

fn round_trip<T>(golden: Value) -> T
where
    T: Message + Name + Default + Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_vec(&golden).expect("fixture JSON");
    let value: T = decode_management_json(&json).expect("strict generated management boundary");
    assert_eq!(serde_json::to_value(&value).unwrap(), golden);
    let binary = value.encode_to_vec();
    assert_eq!(T::decode(binary.as_slice()).unwrap(), value);
    assert!(
        json.len() <= 4096 && binary.len() <= 4096,
        "fixture fit only"
    );
    value
}

fn rejects<T: DeserializeOwned + Name>(input: &[u8]) {
    let Err(error) = decode_management_json::<T>(input) else {
        panic!("strict management JSON must reject this wire input");
    };
    assert_eq!(error.to_string(), "invalid or oversized management JSON");
}

#[test]
fn request_preserves_all_seven_fields_and_exact_observed_pin_bytes() {
    let request: proto::CheckRuntimeAuthorityRequest = round_trip(fixture("request"));
    assert_eq!(request.schema_version, 1);
    assert_eq!(
        request.action,
        i32::from(proto::RuntimeAuthorityAction::CheckCurrentOperation)
    );
    assert_eq!(
        request.observed_controller_certificate_sha256,
        vec![0xab; 32]
    );
    assert_eq!(request.target.as_ref().unwrap().generation, LARGE);
    assert_eq!(request.target.as_ref().unwrap().fencing_token, u64::MAX);
    assert_eq!(fixture("request").as_object().unwrap().len(), 7);
    let mut maximum = fixture("request");
    maximum["target"]["generation"] = json!(u64::MAX.to_string());
    let maximum: proto::CheckRuntimeAuthorityRequest = round_trip(maximum);
    assert_eq!(maximum.target.unwrap().generation, u64::MAX);
    // These bytes are an untrusted synthetic observation, not a TLS certificate.
}

#[test]
fn snapshot_preserves_the_complete_sixteen_field_safe_projection() {
    let snapshot: proto::RuntimeAuthoritySnapshot = round_trip(fixture("snapshot"));
    assert_eq!(fixture("snapshot").as_object().unwrap().len(), 16);
    assert_eq!(snapshot.agent_identity_id, "host-agent-a");
    assert_eq!(snapshot.observed_controller_identity_id, "controller-a");
    assert_eq!(snapshot.peer_policy_version, "policy-1");
    assert_eq!(snapshot.enrollment_version, "enrollment-1");
    assert_eq!(snapshot.host_policy_version, "host-1");
    assert_eq!(
        snapshot.desired_state,
        i32::from(proto::ProxyDesiredState::Serving)
    );
    assert_eq!(
        snapshot.observed_state,
        i32::from(proto::ProxyObservedState::Reconciling)
    );
    assert_eq!(snapshot.config_hash, "a".repeat(64));
    assert_eq!(snapshot.checked_at_unix_us, LARGE);
    assert_eq!(snapshot.lease_expires_at_unix_us, 9_007_199_254_741_000);
    let mut maximum = fixture("snapshot");
    maximum["target"]["generation"] = json!(u64::MAX.to_string());
    let maximum: proto::RuntimeAuthoritySnapshot = round_trip(maximum);
    assert_eq!(maximum.target.unwrap().generation, u64::MAX);
}

#[test]
fn timestamp_round_trips_retain_small_differences_above_js_precision_and_at_u64_max() {
    for (checked, expires, difference) in [
        (LARGE, 9_007_199_254_740_994, 1),
        (LARGE, 9_007_199_254_741_000, 7),
        (LARGE, 9_007_199_254_741_992, 999),
        (18_446_744_073_709_551_614, u64::MAX, 1),
        (18_446_744_073_709_551_608, u64::MAX, 7),
        (18_446_744_073_709_550_616, u64::MAX, 999),
    ] {
        let mut golden = fixture("snapshot");
        golden["checkedAtUnixUs"] = json!(checked.to_string());
        golden["leaseExpiresAtUnixUs"] = json!(expires.to_string());
        let decoded: proto::RuntimeAuthoritySnapshot = round_trip(golden);
        assert_eq!(decoded.checked_at_unix_us, checked);
        assert_eq!(decoded.lease_expires_at_unix_us, expires);
        assert_eq!(
            decoded
                .lease_expires_at_unix_us
                .checked_sub(decoded.checked_at_unix_us),
            Some(difference)
        );
    }
    let mut golden = fixture("snapshot");
    golden["checkedAtUnixUs"] = json!(u64::MAX.to_string());
    golden["leaseExpiresAtUnixUs"] = json!(u64::MAX.to_string());
    let decoded: proto::RuntimeAuthoritySnapshot = round_trip(golden);
    assert_eq!(decoded.checked_at_unix_us, u64::MAX);
    assert_eq!(decoded.lease_expires_at_unix_us, u64::MAX);
    // Integer preservation, not remote-clock freshness or a renewed lease.
}

fn reject_noncanonical_u64<T: DeserializeOwned + Name>(name: &str, pointers: &[&str]) {
    let golden = fixture(name);
    assert!(decode_management_json::<T>(&serde_json::to_vec(&golden).unwrap()).is_ok());
    for pointer in pointers {
        for invalid in [
            json!(1),
            json!(LARGE),
            json!(u64::MAX),
            json!(-1),
            json!(1.5),
            json!(""),
            json!("01"),
            json!("+1"),
            json!("-1"),
            json!("1.0"),
            json!("1e3"),
            json!(" 1"),
            json!("1 "),
            json!("18446744073709551616"),
            Value::Null,
        ] {
            let mut bad = golden.clone();
            *bad.pointer_mut(pointer).expect("existing uint64 field") = invalid;
            rejects::<T>(&serde_json::to_vec(&bad).unwrap());
        }
    }
}

#[test]
fn strict_new_wire_json_requires_canonical_strings_for_every_uint64() {
    reject_noncanonical_u64::<proto::CheckRuntimeAuthorityRequest>(
        "request",
        &["/target/generation", "/target/fencingToken"],
    );
    reject_noncanonical_u64::<proto::RuntimeAuthoritySnapshot>(
        "snapshot",
        &[
            "/target/generation",
            "/target/fencingToken",
            "/checkedAtUnixUs",
            "/leaseExpiresAtUnixUs",
        ],
    );
}

#[test]
fn strict_boundary_refuses_original_decoded_duplicates_and_alias_pairs() {
    for text in [
        r#"{"schemaVersion":1,"schemaVersion":1}"#,
        r#"{"schemaVersion":1,"schema_version":1}"#,
        r#"{"operationId":"a","\u006fperationId":"a"}"#,
        r#"{"operationId":"a","operation_id":"a"}"#,
        r#"{"target":null,"target":{}}"#,
        r#"{"target":{"generation":"1","generation":"2"}}"#,
        r#"{"target":{"fencingToken":"1","fencing_token":"1"}}"#,
        r#"{"action":null,"action":"RUNTIME_AUTHORITY_ACTION_CHECK_CURRENT_OPERATION"}"#,
        r#"{"observedControllerCertificateSha256":"","observed_controller_certificate_sha256":""}"#,
    ] {
        rejects::<proto::CheckRuntimeAuthorityRequest>(text.as_bytes());
    }
    for text in [
        r#"{"checkedAtUnixUs":"1","checkedAtUnixUs":"1"}"#,
        r#"{"checkedAtUnixUs":"1","\u0063heckedAtUnixUs":"1"}"#,
        r#"{"checkedAtUnixUs":"1","checked_at_unix_us":"1"}"#,
        r#"{"leaseExpiresAtUnixUs":"1","lease_expires_at_unix_us":"1"}"#,
        r#"{"peerPolicyVersion":"a","peer_policy_version":"a"}"#,
        r#"{"target":null,"target":{}}"#,
        r#"{"target":{"generation":"1","generation":"2"}}"#,
        r#"{"desiredState":null,"desiredState":"PROXY_DESIRED_STATE_SERVING"}"#,
    ] {
        rejects::<proto::RuntimeAuthoritySnapshot>(text.as_bytes());
    }
    // Valid single snake_case spellings remain compatible, unlike alias pairs.
    let request: proto::CheckRuntimeAuthorityRequest = decode_management_json(
        br#"{"schema_version":1,"operation_id":"op","action":1,"target":{"generation":"1","fencing_token":"7"}}"#,
    ).unwrap();
    assert_eq!(request.target.unwrap().fencing_token, 7);
    let snapshot: proto::RuntimeAuthoritySnapshot = decode_management_json(
        br#"{"checked_at_unix_us":"9007199254740993","lease_expires_at_unix_us":"18446744073709551615"}"#,
    ).unwrap();
    assert_eq!(snapshot.checked_at_unix_us, LARGE);
    assert_eq!(snapshot.lease_expires_at_unix_us, u64::MAX);
}

#[test]
fn unknown_authority_fields_nested_claims_and_enums_are_refused() {
    for field in [
        "workerId",
        "role",
        "spec",
        "secretRef",
        "certificate",
        "ensure",
        "ready",
        "admitting",
        "engineId",
    ] {
        let mut request = fixture("request");
        request[field] = json!("WIRE_CANARY");
        rejects::<proto::CheckRuntimeAuthorityRequest>(&serde_json::to_vec(&request).unwrap());
        let mut snapshot = fixture("snapshot");
        snapshot[field] = json!("WIRE_CANARY");
        rejects::<proto::RuntimeAuthoritySnapshot>(&serde_json::to_vec(&snapshot).unwrap());
    }
    for field in ["commandId", "workerId", "ready"] {
        let mut request = fixture("request");
        request["target"][field] = json!("WIRE_CANARY");
        rejects::<proto::CheckRuntimeAuthorityRequest>(&serde_json::to_vec(&request).unwrap());
        let mut snapshot = fixture("snapshot");
        snapshot["target"][field] = json!("WIRE_CANARY");
        rejects::<proto::RuntimeAuthoritySnapshot>(&serde_json::to_vec(&snapshot).unwrap());
    }
    for invalid in [
        json!(777),
        json!(-1),
        json!("RUNTIME_AUTHORITY_ACTION_ENSURE"),
    ] {
        let mut request = fixture("request");
        request["action"] = invalid.clone();
        rejects::<proto::CheckRuntimeAuthorityRequest>(&serde_json::to_vec(&request).unwrap());
        let mut snapshot = fixture("snapshot");
        snapshot["action"] = invalid;
        rejects::<proto::RuntimeAuthoritySnapshot>(&serde_json::to_vec(&snapshot).unwrap());
    }
    for field in ["desiredState", "observedState"] {
        for invalid in [json!(777), json!(-1), json!("FUTURE_STATE")] {
            let mut snapshot = fixture("snapshot");
            snapshot[field] = invalid;
            rejects::<proto::RuntimeAuthoritySnapshot>(&serde_json::to_vec(&snapshot).unwrap());
        }
    }
}

#[test]
fn wire_defaults_zero_times_and_short_pins_are_not_live_authority_validation() {
    let request: proto::CheckRuntimeAuthorityRequest = decode_management_json(b"{}").unwrap();
    assert_eq!(request, proto::CheckRuntimeAuthorityRequest::default());
    assert_eq!(
        request,
        proto::CheckRuntimeAuthorityRequest::decode(&[][..]).unwrap()
    );
    assert_eq!(request.schema_version, 0);
    assert!(request.target.is_none() && request.observed_controller_certificate_sha256.is_empty());
    assert_eq!(
        request.action,
        i32::from(proto::RuntimeAuthorityAction::Unspecified)
    );
    let snapshot: proto::RuntimeAuthoritySnapshot = decode_management_json(b"{}").unwrap();
    assert_eq!(snapshot, proto::RuntimeAuthoritySnapshot::default());
    assert_eq!(
        snapshot,
        proto::RuntimeAuthoritySnapshot::decode(&[][..]).unwrap()
    );
    let zero: proto::RuntimeAuthoritySnapshot =
        decode_management_json(br#"{"checkedAtUnixUs":"0","leaseExpiresAtUnixUs":"0"}"#).unwrap();
    assert_eq!(zero, snapshot);
    let short: proto::CheckRuntimeAuthorityRequest =
        decode_management_json(br#"{"observedControllerCertificateSha256":"qw=="}"#).unwrap();
    assert_eq!(short.observed_controller_certificate_sha256, [0xab]);
    // Future live service owns completeness, exact pin length, caller/lease
    // verification and <=4096-byte enforcement; this decoder does not add them.
}

#[test]
fn control_descriptor_has_one_unary_non_executing_authority_method_and_two_actions() {
    let set = prost_types::FileDescriptorSet::decode(DESCRIPTORS).unwrap();
    let file = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("apex/v1/proxy_runtime_authority.proto"))
        .expect("new canonical authority descriptor");
    assert_eq!(file.package.as_deref(), Some("apex.v1"));
    assert_eq!(file.service.len(), 1);
    let service = &file.service[0];
    assert_eq!(service.name.as_deref(), Some("RuntimeAuthorityService"));
    assert_eq!(service.method.len(), 1);
    let method = &service.method[0];
    assert_eq!(method.name.as_deref(), Some("CheckRuntimeAuthority"));
    assert_eq!(
        method.input_type.as_deref(),
        Some(".apex.v1.CheckRuntimeAuthorityRequest")
    );
    assert_eq!(
        method.output_type.as_deref(),
        Some(".apex.v1.RuntimeAuthoritySnapshot")
    );
    assert!(!method.client_streaming.unwrap_or(false) && !method.server_streaming.unwrap_or(false));
    assert_eq!(file.enum_type.len(), 1);
    let action = &file.enum_type[0];
    assert_eq!(action.name.as_deref(), Some("RuntimeAuthorityAction"));
    let values: Vec<_> = action
        .value
        .iter()
        .map(|value| (value.name.as_deref(), value.number))
        .collect();
    assert_eq!(
        values,
        [
            (Some("RUNTIME_AUTHORITY_ACTION_UNSPECIFIED"), Some(0)),
            (
                Some("RUNTIME_AUTHORITY_ACTION_CHECK_CURRENT_OPERATION"),
                Some(1)
            ),
        ]
    );
    assert_eq!(file.message_type.len(), 2);
    assert_eq!(
        <proto::CheckRuntimeAuthorityRequest as Name>::full_name(),
        "apex.v1.CheckRuntimeAuthorityRequest"
    );
    assert_eq!(
        <proto::RuntimeAuthoritySnapshot as Name>::full_name(),
        "apex.v1.RuntimeAuthoritySnapshot"
    );
}

#[test]
fn generated_authority_client_and_server_select_the_redacted_prost_codec() {
    let generated = include_str!(concat!(env!("OUT_DIR"), "/apex.v1.rs"));
    for module in [
        "runtime_authority_service_client",
        "runtime_authority_service_server",
    ] {
        let marker = format!("pub mod {module} {{");
        let tail = generated
            .split_once(marker.as_str())
            .expect("generated authority module")
            .1;
        let body = tail.split("\npub mod ").next().unwrap();
        assert_eq!(
            body.matches("let codec = apex_contract::RedactedProstCodec::default();")
                .count(),
            1,
            "{module}: the single authority method must select the redacted codec",
        );
        assert!(
            !body.contains("tonic_prost::ProstCodec"),
            "{module}: raw codec forbidden"
        );
    }
    // Selection evidence only: malformed-RPC status behavior and the global
    // builder's effects on legacy services require main's broader regressions.
}
