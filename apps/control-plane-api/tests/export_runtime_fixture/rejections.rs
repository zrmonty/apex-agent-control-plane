use super::support::{fixture, rich_fixture};
use apex_control_plane_api::{
    McpProxyRevision, ProxyTransport, RuntimeDeploymentBindings, SecretRef, compile_runtime_config,
};
use serde_json::{Value, json};

type Mutation = fn(&mut McpProxyRevision, &mut RuntimeDeploymentBindings);

fn rejects(cases: &[(&str, Mutation)]) {
    for (name, mutate) in cases {
        let (mut revision, mut bindings, _) = fixture();
        compile_runtime_config(&revision, &bindings).expect("valid baseline must compile first");
        mutate(&mut revision, &mut bindings);
        assert!(
            compile_runtime_config(&revision, &bindings).is_err(),
            "{name}"
        );
    }
}

#[test]
fn missing_security_bindings_and_unsupported_enforcement_fail_closed() {
    rejects(&[
        ("empty scope", |_, b| b.scope.workspace_id.clear()),
        ("invalid namespace", |_, b| {
            b.scope.namespace_id = "../other".into()
        }),
        ("zero generation", |_, b| b.generation = 0),
        ("empty resource", |_, b| b.resource_url.clear()),
        ("wrong audience", |_, b| {
            b.auth.audience = "https://other.apex.test/mcp".into()
        }),
        ("missing issuer", |_, b| b.auth.issuer.clear()),
        ("insecure JWKS", |_, b| {
            b.auth.jwks_uri = "http://issuer.example.test/jwks".into()
        }),
        ("missing scopes", |_, b| b.auth.required_scopes.clear()),
        ("missing identity", |_, b| {
            b.auth.workload_identity_ref.clear()
        }),
        ("raw identity", |_, b| {
            b.auth.workload_identity_ref = "raw-credential".into()
        }),
        ("missing telemetry", |_, b| b.telemetry = Default::default()),
        ("telemetry stage overflow", |_, b| {
            b.telemetry.max_stages = 33
        }),
        ("telemetry queue overflow", |_, b| {
            b.telemetry.max_export_queue_bytes = u64::MAX
        }),
        ("bad control hash", |r, _| {
            r.config_hash = "sha256:invalid".into()
        }),
        ("unauthenticated ingress", |r, _| {
            r.spec.ingress.inbound_authentication_required = false
        }),
        ("stdio shared ingress", |r, _| {
            r.spec.ingress.transport = ProxyTransport::Stdio
        }),
        ("unknown MCP revision", |r, _| {
            r.spec.ingress.protocol_revision = "2099-01-01".into()
        }),
        ("rootful runtime", |r, _| {
            r.spec.runtime_profile.rootless = false
        }),
        ("writable filesystem", |r, _| {
            r.spec.runtime_profile.filesystem_policy = "read-write".into()
        }),
        ("unrestricted network", |r, _| {
            r.spec.runtime_profile.network_policy = "allow-all".into()
        }),
        ("ingress allocation mismatch", |r, _| {
            r.spec.ingress.path = "/different".into()
        }),
        ("upstream credentials in URL", |r, _| {
            r.spec.upstreams[0].endpoint_or_command_ref =
                "https://user:password@portfolio-api.apex.test/mcp".into()
        }),
        ("undiscovered upstream", |r, _| {
            r.spec.upstreams[0].tool_catalog_hash = None
        }),
    ]);
}

#[test]
fn images_require_catalog_membership_and_a_matching_pullable_digest() {
    rejects(&[
        ("catalog miss", |_, b| b.image_catalog.clear()),
        ("digest is not an image reference", |r, b| {
            b.image_catalog.insert(
                r.spec.runtime_profile.image_digest.clone(),
                r.spec.runtime_profile.image_digest.clone(),
            );
        }),
        ("mutable image tag", |r, b| {
            b.image_catalog.insert(
                r.spec.runtime_profile.image_digest.clone(),
                "registry.example.test/apex/gateway:latest".into(),
            );
        }),
        ("wrong image digest", |r, b| {
            b.image_catalog.insert(
                r.spec.runtime_profile.image_digest.clone(),
                format!(
                    "registry.example.test/apex/gateway@sha256:{}",
                    "f".repeat(64)
                ),
            );
        }),
    ]);
}

#[test]
fn secret_metadata_must_equal_the_declared_union() {
    rejects(&[
        ("missing secret", |_, b| b.secret_refs.clear()),
        ("extra secret", |_, b| {
            b.secret_refs
                .push(SecretRef::new("secret://vault/unrelated").unwrap())
        }),
        ("duplicate metadata", |_, b| {
            b.secret_refs.push(b.secret_refs[0].clone())
        }),
        ("malformed reference", |r, b| {
            r.spec.upstreams[0].credential_ref = Some(SecretRef::new("secret://").unwrap());
            b.secret_refs = vec![SecretRef::new("secret://").unwrap()];
        }),
    ]);
    let (revision, mut bindings, _) = rich_fixture();
    compile_runtime_config(&revision, &bindings).unwrap();
    bindings
        .secret_refs
        .retain(|r| r.as_str() != "secret://vault/auth/outbound");
    assert!(compile_runtime_config(&revision, &bindings).is_err());
}

#[test]
fn every_exposed_tool_needs_complete_approved_schema_and_output_profile() {
    rejects(&[
        ("missing schema", |_, b| b.tool_schemas.clear()),
        ("missing input schema", |_, b| {
            b.tool_schemas[0].input_schema_json.clear()
        }),
        ("missing output schema", |_, b| {
            b.tool_schemas[0].output_schema_json.clear()
        }),
        ("invalid schema JSON", |_, b| {
            b.tool_schemas[0].input_schema_json = "{".into()
        }),
        ("missing profile", |_, b| {
            b.tool_schemas[0].output_profile_id.clear()
        }),
        ("unapproved profile", |_, b| {
            b.approved_output_profiles.clear()
        }),
        ("missing schema hash", |_, b| {
            b.tool_schemas[0].schema_hash.clear()
        }),
        ("wrong tool", |_, b| {
            b.tool_schemas[0].tool_name = "unexposed.tool".into()
        }),
        ("duplicate schema", |_, b| {
            b.tool_schemas.push(b.tool_schemas[0].clone())
        }),
    ]);
}

const REFERENCE_FREE_SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "value": {"type": "string"},
        "alias": {"type": "string"}
    }
}"#;

#[test]
fn valid_shape_reference_free_schema_compiles_without_rewriting() {
    let (revision, mut bindings, _) = fixture();
    bindings.tool_schemas[0].input_schema_json = REFERENCE_FREE_SCHEMA.into();
    bindings.tool_schemas[0].output_schema_json = REFERENCE_FREE_SCHEMA.into();

    let config = compile_runtime_config(&revision, &bindings)
        .expect("reference-free object schema must compile");
    assert_eq!(
        config.tool_schemas[0].input_schema_json,
        REFERENCE_FREE_SCHEMA
    );
    assert_eq!(
        config.tool_schemas[0].output_schema_json,
        REFERENCE_FREE_SCHEMA
    );
}

fn rejects_schema_reference(schema: &Value) {
    for input_schema in [true, false] {
        let (revision, mut bindings, _) = fixture();
        // Use the same serialized shape as the rejection case, minus only $ref.
        let baseline: Value = serde_json::from_str(REFERENCE_FREE_SCHEMA).unwrap();
        bindings.tool_schemas[0].input_schema_json = baseline.to_string();
        bindings.tool_schemas[0].output_schema_json = baseline.to_string();
        compile_runtime_config(&revision, &bindings)
            .expect("reference-free baseline must compile before adding only $ref");

        let field = if input_schema {
            &mut bindings.tool_schemas[0].input_schema_json
        } else {
            &mut bindings.tool_schemas[0].output_schema_json
        };
        *field = schema.to_string();
        assert!(
            compile_runtime_config(&revision, &bindings).is_err(),
            "otherwise-valid schema with $ref must be rejected (input_schema={input_schema})"
        );
    }
}

#[test]
fn valid_shape_top_level_remote_schema_reference_is_rejected() {
    let mut schema: Value = serde_json::from_str(REFERENCE_FREE_SCHEMA).unwrap();
    schema["$ref"] = json!("https://other.apex.test/schema");
    rejects_schema_reference(&schema);
}

#[test]
fn valid_shape_nested_local_schema_reference_is_rejected() {
    let mut schema: Value = serde_json::from_str(REFERENCE_FREE_SCHEMA).unwrap();
    // The local target exists; rejection must not depend on an unresolved path.
    schema["properties"]["alias"]["$ref"] = json!("#/properties/value");
    rejects_schema_reference(&schema);
}

#[test]
fn network_grants_cannot_add_or_widen_declared_destinations() {
    rejects(&[
        ("missing grant", |_, b| b.network_grants.clear()),
        ("wrong host", |_, b| {
            b.network_grants[0].host = "other.apex.test".into()
        }),
        ("wrong port", |_, b| b.network_grants[0].port = 8443),
        ("duplicate grant", |_, b| {
            b.network_grants.push(b.network_grants[0].clone())
        }),
        ("private widening", |_, b| {
            b.network_grants[0].private_destination = true
        }),
        ("invalid CIDR", |_, b| {
            b.network_grants[0].approved_cidrs = vec!["not-a-cidr".into()]
        }),
        ("unrestricted CIDR", |_, b| {
            b.network_grants[0].approved_cidrs = vec!["0.0.0.0/0".into()]
        }),
        ("loopback CIDR", |_, b| {
            b.network_grants[0].approved_cidrs = vec!["127.0.0.1/32".into()]
        }),
        ("metadata CIDR", |_, b| {
            b.network_grants[0].approved_cidrs = vec!["169.254.169.254/32".into()]
        }),
    ]);
}

#[test]
fn invalid_resource_units_are_rejected_instead_of_rounded_or_defaulted() {
    rejects(&[
        ("zero CPU", |r, _| {
            r.spec.runtime_profile.cpu_limit = "0m".into()
        }),
        ("fractional millicpu", |r, _| {
            r.spec.runtime_profile.cpu_limit = "0.5m".into()
        }),
        ("CPU overflow", |r, _| {
            r.spec.runtime_profile.cpu_limit = "18446744073709551616".into()
        }),
        ("zero memory", |r, _| {
            r.spec.runtime_profile.memory_limit = "0Mi".into()
        }),
        ("unknown memory unit", |r, _| {
            r.spec.runtime_profile.memory_limit = "256Mystery".into()
        }),
        ("memory overflow", |r, _| {
            r.spec.runtime_profile.memory_limit = "18446744073709551615Gi".into()
        }),
        ("missing PID limit", |_, b| b.pid_limit = 0),
    ]);
}
