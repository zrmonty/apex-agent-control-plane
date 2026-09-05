//! Separately generated agent wire coverage over shared synthetic JSON.
//! No application import, listener, TLS attestation, current lease or permission.
use apex_proxy_runtime_agent::{FILE_DESCRIPTOR_SET, proto};
use prost::{Message, Name};
use prost_types::{DescriptorProto, FileDescriptorProto, field_descriptor_proto::Type};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const LARGE: u64 = 9_007_199_254_740_993;
const FIXTURE: &str = include_str!("../../../contracts/fixtures/mcp-proxy/runtime-authority.json");

fn fixture(name: &str) -> Value {
    serde_json::from_str::<Value>(FIXTURE).expect("shared wire fixture")[name].clone()
}

fn round_trip<T>(golden: Value) -> T
where
    T: Message + Default + Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_vec(&golden).expect("fixture JSON");
    // Generated serde alone, deliberately not the app's strict JSON boundary.
    let value: T = serde_json::from_slice(&json).expect("agent generated ProtoJSON");
    assert_eq!(serde_json::to_value(&value).unwrap(), golden);
    let binary = value.encode_to_vec();
    assert_eq!(T::decode(binary.as_slice()).unwrap(), value);
    assert!(
        json.len() <= 4096 && binary.len() <= 4096,
        "fixture fit only"
    );
    value
}

#[test]
fn independent_request_generator_retains_all_fields_pin_and_six_field_target() {
    let request: proto::CheckRuntimeAuthorityRequest = round_trip(fixture("request"));
    assert_eq!(
        request.observed_controller_certificate_sha256,
        vec![0xab; 32]
    );
    assert_eq!(
        request.target,
        Some(proto::RuntimeTarget {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            proxy_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001".into(),
            revision_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002".into(),
            generation: LARGE,
            fencing_token: u64::MAX,
        })
    );
    assert_eq!(
        request.action,
        i32::from(proto::RuntimeAuthorityAction::CheckCurrentOperation)
    );
    assert_eq!(
        <proto::CheckRuntimeAuthorityRequest as Name>::full_name(),
        "apex.v1.CheckRuntimeAuthorityRequest"
    );
    let mut maximum = fixture("request");
    maximum["target"]["generation"] = json!(u64::MAX.to_string());
    let maximum: proto::CheckRuntimeAuthorityRequest = round_trip(maximum);
    assert_eq!(maximum.target.unwrap().generation, u64::MAX);
}

#[test]
fn independent_snapshot_generator_retains_all_sixteen_fields_and_policy_versions() {
    let snapshot: proto::RuntimeAuthoritySnapshot = round_trip(fixture("snapshot"));
    assert_eq!(fixture("snapshot").as_object().unwrap().len(), 16);
    assert_eq!(snapshot.target.unwrap().fencing_token, u64::MAX);
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
    assert_eq!(
        <proto::RuntimeAuthoritySnapshot as Name>::full_name(),
        "apex.v1.RuntimeAuthoritySnapshot"
    );
    let mut maximum = fixture("snapshot");
    maximum["target"]["generation"] = json!(u64::MAX.to_string());
    let maximum: proto::RuntimeAuthoritySnapshot = round_trip(maximum);
    assert_eq!(maximum.target.unwrap().generation, u64::MAX);
}

#[test]
fn independent_snapshot_codecs_preserve_microsecond_differences_and_full_uint64() {
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
        let value: proto::RuntimeAuthoritySnapshot = round_trip(golden);
        assert_eq!(value.checked_at_unix_us, checked);
        assert_eq!(value.lease_expires_at_unix_us, expires);
        assert_eq!(
            value
                .lease_expires_at_unix_us
                .checked_sub(value.checked_at_unix_us),
            Some(difference)
        );
    }
    let mut golden = fixture("snapshot");
    golden["checkedAtUnixUs"] = json!(u64::MAX.to_string());
    golden["leaseExpiresAtUnixUs"] = json!(u64::MAX.to_string());
    let maximum: proto::RuntimeAuthoritySnapshot = round_trip(golden);
    assert_eq!(maximum.checked_at_unix_us, u64::MAX);
    assert_eq!(maximum.lease_expires_at_unix_us, u64::MAX);
}

#[test]
fn independently_pinned_timestamp_tags_and_varints_match_the_generated_binary() {
    // Literal tag 15/varint and tag 16/varint, 2^53+1 and 2^64-1.
    // This expected sequence is not built by another protobuf encoder.
    let binary = [
        0x78, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10, 0x80, 0x01, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ];
    let expected = proto::RuntimeAuthoritySnapshot {
        checked_at_unix_us: LARGE,
        lease_expires_at_unix_us: u64::MAX,
        ..Default::default()
    };
    assert_eq!(expected.encode_to_vec(), binary);
    assert_eq!(
        proto::RuntimeAuthoritySnapshot::decode(binary.as_slice()).unwrap(),
        expected
    );
}

#[test]
fn independent_pin_tag_length_and_base64_are_exact_not_a_certificate_claim() {
    // Field 7, length-delimited, 32 bytes of synthetic 0xab.
    let mut binary = vec![0x3a, 0x20];
    binary.extend_from_slice(&[0xab; 32]);
    let request = proto::CheckRuntimeAuthorityRequest::decode(binary.as_slice()).unwrap();
    assert_eq!(
        request.observed_controller_certificate_sha256,
        vec![0xab; 32]
    );
    assert_eq!(request.encode_to_vec(), binary);
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        json!({
            "observedControllerCertificateSha256": "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="
        })
    );
}

fn file<'a>(set: &'a prost_types::FileDescriptorSet, name: &str) -> &'a FileDescriptorProto {
    set.file
        .iter()
        .find(|file| file.name.as_deref() == Some(name))
        .expect("canonical descriptor file")
}

fn message<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a DescriptorProto {
    file.message_type
        .iter()
        .find(|value| value.name.as_deref() == Some(name))
        .expect("canonical message")
}

fn fields(message: &DescriptorProto, expected: &[(i32, &str, Type, Option<&str>)]) {
    assert_eq!(message.field.len(), expected.len());
    for (field, (number, name, kind, type_name)) in message.field.iter().zip(expected) {
        assert_eq!(field.number, Some(*number));
        assert_eq!(field.name.as_deref(), Some(*name));
        assert_eq!(field.r#type, Some(i32::from(*kind)));
        assert_eq!(field.type_name.as_deref(), *type_name);
        assert_eq!(field.label, Some(1), "singular fields only");
        assert!(field.oneof_index.is_none() && !field.proto3_optional.unwrap_or(false));
    }
    assert!(message.oneof_decl.is_empty() && message.nested_type.is_empty());
}

#[test]
fn independent_descriptor_pins_all_authority_fields_and_unchanged_runtime_target() {
    let set = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let authority = file(&set, "apex/v1/proxy_runtime_authority.proto");
    assert_eq!(authority.message_type.len(), 2);
    fields(
        message(authority, "CheckRuntimeAuthorityRequest"),
        &[
            (1, "schema_version", Type::Uint32, None),
            (2, "target", Type::Message, Some(".apex.v1.RuntimeTarget")),
            (3, "operation_id", Type::String, None),
            (4, "command_id", Type::String, None),
            (
                5,
                "action",
                Type::Enum,
                Some(".apex.v1.RuntimeAuthorityAction"),
            ),
            (6, "installation_id", Type::String, None),
            (
                7,
                "observed_controller_certificate_sha256",
                Type::Bytes,
                None,
            ),
        ],
    );
    fields(
        message(authority, "RuntimeAuthoritySnapshot"),
        &[
            (1, "schema_version", Type::Uint32, None),
            (2, "target", Type::Message, Some(".apex.v1.RuntimeTarget")),
            (3, "operation_id", Type::String, None),
            (4, "command_id", Type::String, None),
            (
                5,
                "action",
                Type::Enum,
                Some(".apex.v1.RuntimeAuthorityAction"),
            ),
            (6, "installation_id", Type::String, None),
            (7, "agent_identity_id", Type::String, None),
            (8, "observed_controller_identity_id", Type::String, None),
            (9, "peer_policy_version", Type::String, None),
            (10, "enrollment_version", Type::String, None),
            (11, "host_policy_version", Type::String, None),
            (
                12,
                "desired_state",
                Type::Enum,
                Some(".apex.v1.ProxyDesiredState"),
            ),
            (
                13,
                "observed_state",
                Type::Enum,
                Some(".apex.v1.ProxyObservedState"),
            ),
            (14, "config_hash", Type::String, None),
            (15, "checked_at_unix_us", Type::Uint64, None),
            (16, "lease_expires_at_unix_us", Type::Uint64, None),
        ],
    );
    let runtime = file(&set, "apex/v1/proxy_runtime.proto");
    fields(
        message(runtime, "RuntimeTarget"),
        &[
            (1, "workspace_id", Type::String, None),
            (2, "namespace_id", Type::String, None),
            (3, "proxy_id", Type::String, None),
            (4, "revision_id", Type::String, None),
            (5, "generation", Type::Uint64, None),
            (6, "fencing_token", Type::Uint64, None),
        ],
    );
    // Exact positive field sets exclude ready/admit/Ensure/worker/spec/secrets.
}

#[test]
fn independent_service_descriptor_has_only_unary_current_operation_check() {
    let set = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let authority = file(&set, "apex/v1/proxy_runtime_authority.proto");
    assert_eq!(authority.package.as_deref(), Some("apex.v1"));
    assert_eq!(authority.service.len(), 1);
    let service = &authority.service[0];
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
    assert_eq!(authority.enum_type.len(), 1);
    let action = &authority.enum_type[0];
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
}

#[test]
fn generated_empty_zero_and_short_pin_messages_do_not_establish_authority() {
    let request: proto::CheckRuntimeAuthorityRequest = serde_json::from_str("{}").unwrap();
    assert_eq!(
        request,
        proto::CheckRuntimeAuthorityRequest::decode(&[][..]).unwrap()
    );
    assert_eq!(request, proto::CheckRuntimeAuthorityRequest::default());
    assert_eq!(request.schema_version, 0);
    assert!(request.target.is_none() && request.observed_controller_certificate_sha256.is_empty());
    assert_eq!(
        request.action,
        i32::from(proto::RuntimeAuthorityAction::Unspecified)
    );
    let snapshot: proto::RuntimeAuthoritySnapshot = serde_json::from_str("{}").unwrap();
    assert_eq!(
        snapshot,
        proto::RuntimeAuthoritySnapshot::decode(&[][..]).unwrap()
    );
    assert_eq!(snapshot, proto::RuntimeAuthoritySnapshot::default());
    let zero: proto::RuntimeAuthoritySnapshot =
        serde_json::from_str(r#"{"checkedAtUnixUs":"0","leaseExpiresAtUnixUs":"0"}"#).unwrap();
    assert_eq!(zero, snapshot);
    let short: proto::CheckRuntimeAuthorityRequest =
        serde_json::from_str(r#"{"observedControllerCertificateSha256":"qw=="}"#).unwrap();
    assert_eq!(short.observed_controller_certificate_sha256, [0xab]);
    // No claim of canonical-u64 or null-first-duplicate rejection by generated
    // serde alone. A future live owner must also reject these incomplete claims.
}
