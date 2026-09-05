//! Compiler contract tests. Main owns Cargo execution and API registration.
//! The export remains in a unique temporary directory for the later TS consumer.

use apex_control_plane_api::{ApprovalMode, compile_runtime_config, runtime_manifest_hash};
use serde_json::json;

#[path = "export_runtime_fixture/rejections.rs"]
mod rejections;
#[path = "export_runtime_fixture/support.rs"]
mod support;

use support::{RUNTIME_HASH, fixture, rich_fixture};

#[test]
fn compile_preserves_complete_golden_and_exports_generated_protojson() {
    let (revision, bindings, mut expected) = fixture();
    let unchanged = revision.clone();
    let config = compile_runtime_config(&revision, &bindings)
        .expect("valid immutable revision must compile");
    expected.runtime_manifest_hash = RUNTIME_HASH.into();
    assert_eq!(
        config, expected,
        "every generated field must survive compilation"
    );
    assert_eq!(
        revision, unchanged,
        "compiler must not mutate control state"
    );
    assert_eq!(config.config_hash, "a".repeat(64));
    assert_ne!(config.runtime_manifest_hash, config.config_hash);
    assert_ne!(
        config.resource_url,
        config.spec.as_ref().unwrap().upstreams[0].endpoint_or_command_ref
    );
    assert_eq!(config.auth.as_ref().unwrap().audience, config.resource_url);
    assert_eq!(runtime_manifest_hash(&config).unwrap(), RUNTIME_HASH);
    let artifact = support::export(&config);
    let decoded: apex_control_plane_api::proto::RuntimeConfiguration =
        apex_control_plane_api::contract_json::decode_management_json(
            &std::fs::read(&artifact).unwrap(),
        )
        .expect("export must satisfy generated strict ProtoJSON");
    assert_eq!(config, decoded);
    println!("APEX_RUNTIME_FIXTURE_PATH={}", artifact.display());
}

#[test]
fn hash_uses_independent_canonical_golden_and_excludes_only_its_own_field() {
    let (_, _, mut config) = fixture();
    assert_eq!(runtime_manifest_hash(&config).unwrap(), RUNTIME_HASH);
    config.runtime_manifest_hash = "c".repeat(64);
    assert_eq!(runtime_manifest_hash(&config).unwrap(), RUNTIME_HASH);
    config.config_hash = "d".repeat(64);
    assert_ne!(runtime_manifest_hash(&config).unwrap(), RUNTIME_HASH);
}

#[test]
fn deployment_changes_hash_without_rewriting_control_hash() {
    let (revision, mut bindings, _) = fixture();
    let original = compile_runtime_config(&revision, &bindings).unwrap();
    bindings.generation = 9_007_199_254_740_993;
    let next = compile_runtime_config(&revision, &bindings).unwrap();
    assert_eq!(next.config_hash, original.config_hash);
    assert_ne!(next.runtime_manifest_hash, original.runtime_manifest_hash);
    assert_eq!(
        next.runtime_manifest_hash,
        runtime_manifest_hash(&next).unwrap()
    );
    let json = serde_json::to_value(next).unwrap();
    assert_eq!(json["generation"], "9007199254740993");
    assert_eq!(json["memoryBytes"], "268435456");
    assert_eq!(json["telemetry"]["maxExportQueueBytes"], "8388608");
}

#[test]
fn all_nested_arrays_auth_grants_and_output_profiles_survive() {
    let (revision, bindings, expected_spec) = rich_fixture();
    let config = compile_runtime_config(&revision, &bindings).unwrap();
    assert_eq!(config.spec.as_ref(), Some(&expected_spec));
    assert_eq!(config.tool_schemas, bindings.tool_schemas);
    assert_eq!(config.network_grants, bindings.network_grants);
    assert_eq!(config.auth.as_ref(), Some(&bindings.auth));
    assert_eq!(config.telemetry.as_ref(), Some(&bindings.telemetry));
    assert_eq!(config.cpu_millis, 500);
    assert_eq!(config.memory_bytes, 268_435_456);
    assert_eq!(config.pid_limit, 128);
    assert_eq!(config.approval_mode, 3);
    let mut actual_refs = config.secret_refs.clone();
    actual_refs.sort();
    assert_eq!(
        actual_refs,
        vec![
            "secret://vault/auth/outbound",
            "secret://vault/upstreams/portfolio-reader",
            "secret://vault/upstreams/quotes-reader",
            "secret://vault/upstreams/shared-ca",
        ]
    );
    assert_eq!(
        config.runtime_manifest_hash,
        runtime_manifest_hash(&config).unwrap()
    );
}

#[test]
fn canonical_approval_modes_map_without_fallback() {
    for (mode, wire_mode, generated_mode) in [
        (ApprovalMode::None, "none", 1),
        (ApprovalMode::Operator, "operator", 2),
        (ApprovalMode::DualOperator, "dual-operator", 3),
    ] {
        let (mut revision, bindings, _) = fixture();
        revision.spec.governance_binding.approval_mode = mode;
        let config = compile_runtime_config(&revision, &bindings).unwrap();
        assert_eq!(config.approval_mode, generated_mode);
        assert_eq!(
            config
                .spec
                .unwrap()
                .governance_binding
                .unwrap()
                .approval_mode,
            wire_mode
        );
    }
}

#[test]
fn integer_units_do_not_round_or_overflow() {
    for (cpu, memory, cpu_millis, memory_bytes) in [
        ("1", "1Gi", 1_000, 1_073_741_824_u64),
        ("125m", "128Mi", 125, 134_217_728),
    ] {
        let (mut revision, bindings, _) = fixture();
        revision.spec.runtime_profile.cpu_limit = cpu.into();
        revision.spec.runtime_profile.memory_limit = memory.into();
        let config = compile_runtime_config(&revision, &bindings).unwrap();
        assert_eq!(config.cpu_millis, cpu_millis);
        assert_eq!(config.memory_bytes, memory_bytes);
    }
}

#[test]
fn manifest_covers_nested_security_fields_and_preserves_array_order() {
    let (_, _, baseline) = fixture();
    let baseline_hash = runtime_manifest_hash(&baseline).unwrap();
    assert_eq!(baseline_hash, RUNTIME_HASH);
    let base = serde_json::to_value(&baseline).unwrap();
    for (pointer, replacement) in [
        (
            "/spec/ingress/allowedOrigins/0",
            json!("https://other.apex.test"),
        ),
        ("/spec/governanceBinding/rateLimit", json!("30/m")),
        ("/spec/governanceBinding/budget", json!("99/d")),
        ("/spec/governanceBinding/concurrencyLimit", json!("2")),
        ("/spec/governanceBinding/retention", json!("10d")),
        ("/toolSchemas/0/outputProfileId", json!("different-profile")),
        ("/networkGrants/0/host", json!("other.apex.test")),
        ("/auth/requiredScopes/0", json!("mcp:other")),
        ("/telemetry/maxStages", json!(16)),
        ("/secretRefs/0", json!("secret://vault/other")),
    ] {
        let mut changed = base.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let config = serde_json::from_value(changed).unwrap();
        assert_ne!(
            runtime_manifest_hash(&config).unwrap(),
            baseline_hash,
            "{pointer}"
        );
    }
    let mut forward = baseline.clone();
    forward.auth.as_mut().unwrap().required_scopes = vec!["mcp:a".into(), "mcp:b".into()];
    let mut reverse = forward.clone();
    reverse.auth.as_mut().unwrap().required_scopes.reverse();
    assert_ne!(
        runtime_manifest_hash(&forward).unwrap(),
        runtime_manifest_hash(&reverse).unwrap()
    );
}

#[test]
fn unknown_generated_approval_enum_returns_static_encoding_error() {
    let (_, _, mut config) = fixture();
    config.approval_mode = 999;
    let error = runtime_manifest_hash(&config).expect_err("unknown enum must not produce a digest");
    assert_eq!(error.code(), "RUNTIME_MANIFEST_ENCODING_FAILED");
    assert_eq!(error.message(), "Runtime manifest cannot be encoded.");
}

#[test]
fn nested_generated_enum_drift_returns_static_encoding_error() {
    let (_, _, mut config) = fixture();
    config
        .spec
        .as_mut()
        .unwrap()
        .ingress
        .as_mut()
        .unwrap()
        .transport = 999;
    let error = runtime_manifest_hash(&config).expect_err("nested unknown enum must fail closed");
    assert_eq!(error.code(), "RUNTIME_MANIFEST_ENCODING_FAILED");
    assert_eq!(error.message(), "Runtime manifest cannot be encoded.");
}
