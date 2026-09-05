//! Actual exporter -> separately generated agent manifest parity, no app import.
//! REQUIRED APEX_RUNTIME_FIXTURE_PATH has no default or repository fallback.
//! Manifest computation is not signature verification or execution authority.

use apex_proxy_runtime_agent::{RuntimeError, proto::RuntimeConfiguration, runtime_manifest_hash};
use prost::Message;
use serde_json::{Value, json};
use std::error::Error as _;

#[path = "runtime_manifest/support.rs"]
mod support;
use support::{BIG, CANARY, MANIFEST, actual_fixture};

#[test]
fn actual_exporter_body_and_known_manifest_survive_agent_json_and_protobuf()
-> Result<(), &'static str> {
    let fixture = actual_fixture()?;
    let configuration = fixture.configuration;
    assert_eq!(configuration.schema_version, 1);
    assert_eq!(configuration.generation, 1);
    assert_eq!(configuration.runtime_manifest_hash, MANIFEST);
    assert_eq!(configuration.config_hash, "a".repeat(64));
    // Whole-body equality plus the pinned artifact SHA catches dropped/defaulted
    // fields; expected data did not come from this agent's serializer.
    assert_eq!(serde_json::to_value(&configuration).unwrap(), fixture.body);
    let json_copy: RuntimeConfiguration = serde_json::from_value(fixture.body).unwrap();
    let binary_copy =
        RuntimeConfiguration::decode(configuration.encode_to_vec().as_slice()).unwrap();
    assert_eq!(json_copy, configuration);
    assert_eq!(binary_copy, configuration);
    for value in [&configuration, &json_copy, &binary_copy] {
        assert_eq!(runtime_manifest_hash(value).unwrap(), MANIFEST);
    }
    Ok(())
}

#[test]
fn root_selfhash_is_excluded_without_mutating_the_generated_input() -> Result<(), &'static str> {
    let baseline = actual_fixture()?.configuration;
    for selfhash in [
        "",
        CANARY,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let mut changed = baseline.clone();
        changed.runtime_manifest_hash = selfhash.into();
        let unchanged = changed.clone();
        assert_eq!(runtime_manifest_hash(&changed).unwrap(), MANIFEST);
        assert_eq!(changed, unchanged);
    }
    Ok(())
}

#[test]
fn control_hash_and_each_mutable_security_field_change_the_recomputed_digest()
-> Result<(), &'static str> {
    let fixture = actual_fixture()?;
    assert_eq!(
        runtime_manifest_hash(&fixture.configuration).unwrap(),
        MANIFEST
    );
    for (pointer, replacement) in [
        ("/configHash", json!("d".repeat(64))),
        ("/resourceUrl", json!("https://other.apex.test/mcp")),
        (
            "/imageRef",
            json!(format!(
                "registry.example.test/apex/gateway@sha256:{}",
                "f".repeat(64)
            )),
        ),
        ("/spec/ingress/inboundAuthenticationRequired", json!(false)),
        ("/spec/runtimeProfile/rootless", json!(false)),
        ("/spec/governanceBinding/budget", json!("99/d")),
        ("/networkGrants/0/host", json!("other.apex.test")),
        ("/auth/audience", json!("https://other.apex.test/mcp")),
        ("/auth/workloadIdentityRef", json!("identity://other")),
        ("/telemetry/maxStages", json!(16)),
        ("/toolSchemas/0/outputProfileId", json!("different-profile")),
        ("/secretRefs/0", json!("secret://vault/other")),
        ("/cpuMillis", json!(1000)),
        ("/memoryBytes", json!("536870912")),
        ("/pidLimit", json!(64)),
    ] {
        let mut body = fixture.body.clone();
        *body.pointer_mut(pointer).unwrap() = replacement;
        let changed: RuntimeConfiguration = serde_json::from_value(body).unwrap();
        assert_ne!(
            runtime_manifest_hash(&changed).unwrap(),
            MANIFEST,
            "{pointer}"
        );
        // This computes a different digest; it does not approve the mutation.
        assert_eq!(changed.runtime_manifest_hash, MANIFEST);
    }
    Ok(())
}

#[test]
fn generation_mutations_keep_exact_uint64_and_independent_expected_hashes()
-> Result<(), &'static str> {
    let baseline = actual_fixture()?.configuration;
    assert_eq!(baseline.generation, 1);
    // Independently prepared using Node crypto over sorted actual-fixture JSON
    // with only generation changed and root selfhash removed. These mutated
    // messages are NOT claimed to be bytes emitted by the original exporter.
    for (generation, expected) in [
        (
            BIG,
            "99e602e092089712ff1ed1e310d8a3bf65897e50d874438da9c3b18876432834",
        ),
        (
            u64::MAX,
            "6280bc0b37a60d1c5a9f70154028db934d3eada89e7953030c27fceae8ac4b9c",
        ),
    ] {
        let changed = RuntimeConfiguration {
            generation,
            ..baseline.clone()
        };
        let json = serde_json::to_value(&changed).unwrap();
        assert_eq!(json["generation"], generation.to_string());
        assert_eq!(json["memoryBytes"], "268435456");
        assert_eq!(json["telemetry"]["maxExportQueueBytes"], "8388608");
        let json_copy: RuntimeConfiguration = serde_json::from_value(json).unwrap();
        let binary_copy = RuntimeConfiguration::decode(changed.encode_to_vec().as_slice()).unwrap();
        assert_eq!(json_copy, changed);
        assert_eq!(binary_copy, changed);
        for value in [&changed, &json_copy, &binary_copy] {
            assert_eq!(runtime_manifest_hash(value).unwrap(), expected);
        }
    }
    Ok(())
}

#[test]
fn generated_array_order_and_opaque_schema_text_remain_hash_significant() -> Result<(), &'static str>
{
    let baseline = actual_fixture()?.configuration;
    assert_eq!(runtime_manifest_hash(&baseline).unwrap(), MANIFEST);
    let mut forward = baseline.clone();
    forward.auth.as_mut().unwrap().required_scopes = vec!["mcp:a".into(), "mcp:b".into()];
    let mut reverse = forward.clone();
    reverse.auth.as_mut().unwrap().required_scopes.reverse();
    assert_ne!(
        runtime_manifest_hash(&forward).unwrap(),
        runtime_manifest_hash(&reverse).unwrap()
    );

    let mut changed = baseline.clone();
    changed.tool_schemas[0].output_schema_json = "{ \"type\": \"object\" }".into();
    assert_eq!(
        serde_json::from_str::<Value>(&baseline.tool_schemas[0].output_schema_json).unwrap(),
        serde_json::from_str::<Value>(&changed.tool_schemas[0].output_schema_json).unwrap()
    );
    assert_ne!(runtime_manifest_hash(&changed).unwrap(), MANIFEST);
    Ok(())
}

#[test]
fn unknown_generated_enums_return_static_errors_without_input_or_cause() -> Result<(), &'static str>
{
    let baseline = actual_fixture()?.configuration;
    for nested in [false, true] {
        let mut changed = baseline.clone();
        changed.resource_url = CANARY.into();
        if nested {
            changed
                .spec
                .as_mut()
                .unwrap()
                .ingress
                .as_mut()
                .unwrap()
                .transport = 999;
        } else {
            changed.approval_mode = 999;
        }
        let error = runtime_manifest_hash(&changed).unwrap_err();
        assert_eq!(error, RuntimeError::ManifestEncodingFailed);
        assert_eq!(error.to_string(), "RUNTIME_MANIFEST_ENCODING_FAILED");
        assert!(error.source().is_none());
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }
    Ok(())
}
