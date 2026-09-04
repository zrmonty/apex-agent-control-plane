use super::{
    ApprovalMode, ArgSchema, ArgSchemaField, CliProfile, DataClassification, EgressDestination,
    ExposedTool, GovernanceBinding, Ingress, NetworkPolicy, PrivateDestinationAllowance,
    ProxyDraft, ProxyId, ProxyRevisionId, ProxySpec, ProxyToolClassification, ProxyTransport,
    RuntimeProfile, SecretRef, UpstreamBinding, parse_proxy_spec_wire_json, validate_proxy_spec,
};
use crate::{ExactScope, proto};
use uuid::Uuid;

const WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e80";
const NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e81";
const OTHER_WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e82";
const OTHER_NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e83";
const PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85";

fn create_proxy_request() -> proto::CreateProxyRequest {
    proto::CreateProxyRequest {
        request_id: REQUEST_ID.to_owned(),
        workspace_id: WORKSPACE_ID.to_owned(),
        namespace_id: NAMESPACE_ID.to_owned(),
        proxy_id: PROXY_ID.to_owned(),
        display_name: "Research MCP proxy".to_owned(),
        slug: "research-mcp-proxy".to_owned(),
        description: Some("Managed proxy for research workflows".to_owned()),
        owner: Some("research-ops".to_owned()),
        tags: vec!["mcp".to_owned(), "research".to_owned()],
    }
}

fn duplicate_idempotency_key_request() -> proto::CreateProxyRequest {
    let mut request = create_proxy_request();
    request.display_name = "Research MCP proxy duplicate".to_owned();
    request
}

fn cross_scope_request() -> proto::CreateProxyRequest {
    let mut request = create_proxy_request();
    request.workspace_id = OTHER_WORKSPACE_ID.to_owned();
    request.namespace_id = OTHER_NAMESPACE_ID.to_owned();
    request
}

#[test]
fn create_proxy_request_fixture_uses_lowercase_uuidv7_ids() {
    let request = create_proxy_request();
    assert_semantic_request_id(request.request_id.as_str());
    assert_eq!(request.workspace_id, WORKSPACE_ID);
    assert_eq!(request.namespace_id, NAMESPACE_ID);
    assert_eq!(request.proxy_id, PROXY_ID);
}

#[test]
fn duplicate_idempotency_key_request_reuses_the_same_request_id() {
    let request = duplicate_idempotency_key_request();
    assert_semantic_request_id(request.request_id.as_str());
    assert_eq!(request.workspace_id, WORKSPACE_ID);
    assert_eq!(request.namespace_id, NAMESPACE_ID);
}

#[test]
fn cross_scope_request_targets_a_different_workspace_and_namespace() {
    let request = cross_scope_request();
    assert_semantic_request_id(request.request_id.as_str());
    assert_eq!(request.workspace_id, OTHER_WORKSPACE_ID);
    assert_eq!(request.namespace_id, OTHER_NAMESPACE_ID);
}

#[test]
fn request_id_helper_rejects_missing_or_non_v7_ids() {
    let missing = String::new();
    let non_v7 = "018f3d4a-8b9c-6d0e-8f12-3a4b5c6d7e85";

    assert!(request_id_is_valid(&missing).is_err());
    assert!(request_id_is_valid(non_v7).is_err());
    assert!(SecretRef::new("raw-token").is_err());
}

#[test]
fn proxy_draft_rejects_an_empty_slug() {
    let error = ProxyDraft::new(
        proxy_id(),
        valid_scope(),
        "Research proxy",
        "",
        valid_proxy_spec(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_DRAFT");
    assert_eq!(
        error.message(),
        "Proxy drafts require a non-empty bounded slug."
    );
}

#[test]
fn proxy_draft_rejects_an_invalid_scope() {
    let error = ProxyDraft::new(
        proxy_id(),
        ExactScope {
            workspace_id: "acme/../other".to_owned(),
            namespace_id: NAMESPACE_ID.to_owned(),
        },
        "Research proxy",
        "research-proxy",
        valid_proxy_spec(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SCOPE");
    assert_eq!(
        error.message(),
        "Proxy drafts require an exact workspace and namespace scope."
    );
}

#[test]
fn proxy_spec_conversion_rejects_an_unknown_transport() {
    let mut spec = valid_proto_spec();
    spec.ingress.as_mut().expect("ingress").transport = 99;

    let error = ProxySpec::try_from(spec).unwrap_err();

    assert_eq!(error.code(), "UNKNOWN_PROXY_TRANSPORT");
    assert_eq!(
        error.message(),
        "Proxy configuration uses an unsupported transport."
    );
}

#[test]
fn proxy_spec_conversion_preserves_explicit_tool_exposure_fields() {
    let spec = ProxySpec::try_from(valid_proto_spec()).expect("valid proxy spec");
    let tool = &spec.exposed_tools[0];

    assert_eq!(tool.upstream_id, "portfolio-upstream");
    assert_eq!(tool.tool_name, "portfolio.read");
    assert_eq!(tool.alias, "portfolio.read");
    assert_eq!(tool.classification, ProxyToolClassification::Read);
}

#[test]
fn proxy_spec_conversion_rejects_an_empty_tool_exposure_field() {
    let mut spec = valid_proto_spec();
    spec.exposed_tools[0].alias.clear();

    let error = ProxySpec::try_from(spec).unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
}

#[test]
fn proxy_spec_conversion_rejects_an_unbound_tool_exposure() {
    let mut spec = valid_proto_spec();
    spec.exposed_tools[0].upstream_id = "missing-upstream".to_owned();

    let error = ProxySpec::try_from(spec).unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
    assert_eq!(
        error.message(),
        "Proxy tool exposure must bind to a declared upstream."
    );
}

#[test]
fn proxy_spec_conversion_preserves_structured_runtime_destinations() {
    let spec = ProxySpec::try_from(valid_proto_spec()).expect("valid proxy spec");

    assert_eq!(spec.runtime_profile.network_policy, "default-deny");
    assert_eq!(spec.runtime_profile.network.destinations.len(), 1);
    assert_eq!(
        spec.runtime_profile.network.destinations[0],
        EgressDestination::Https {
            host: "portfolio-api.apex.test".to_owned(),
            port: 443,
            private_allowance: PrivateDestinationAllowance::Denied,
        }
    );
}

#[test]
fn proxy_spec_conversion_rejects_a_flat_network_policy_without_destinations() {
    let mut spec = valid_proto_spec();
    spec.runtime_profile
        .as_mut()
        .expect("runtime profile")
        .egress_destinations
        .clear();

    let error = ProxySpec::try_from(spec).unwrap_err();

    assert_eq!(error.code(), "MISSING_EGRESS_DESTINATIONS");
}

#[test]
fn validate_proxy_spec_rejects_a_missing_credential_reference() {
    let mut spec = valid_proxy_spec();
    spec.upstreams[0].credential_ref = None;

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "MISSING_CREDENTIAL_REFERENCE");
    assert_eq!(
        error.message(),
        "Each upstream binding must reference a stored credential."
    );
}

#[test]
fn validate_proxy_spec_rejects_an_empty_tool_allowlist() {
    let mut spec = valid_proxy_spec();
    spec.exposed_tools.clear();

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "EMPTY_TOOL_ALLOWLIST");
    assert_eq!(
        error.message(),
        "Proxy revisions must explicitly expose at least one tool."
    );
}

#[test]
fn validate_proxy_spec_rejects_a_shell_enabled_cli_profile() {
    let mut spec = valid_proxy_spec();
    spec.cli_profiles
        .push(valid_cli_profile(true, 5_000, 16_384));

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "CLI_SHELL_DISABLED_REQUIRED");
    assert_eq!(
        error.message(),
        "CLI profiles must disable shell interpretation."
    );
}

#[test]
fn validate_proxy_spec_rejects_an_unbounded_timeout() {
    let mut spec = valid_proxy_spec();
    spec.cli_profiles.push(valid_cli_profile(false, 0, 16_384));

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "CLI_TIMEOUT_REQUIRED");
    assert_eq!(error.message(), "CLI profiles require a bounded timeout.");
}

#[test]
fn validate_proxy_spec_rejects_an_unbounded_output_limit() {
    let mut spec = valid_proxy_spec();
    spec.cli_profiles.push(valid_cli_profile(false, 5_000, 0));

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "CLI_MAX_OUTPUT_REQUIRED");
    assert_eq!(
        error.message(),
        "CLI profiles require a bounded output limit."
    );
}

#[test]
fn validate_proxy_spec_rejects_an_unbounded_domain_string() {
    let mut spec = valid_proxy_spec();
    spec.upstreams[0].server_identity = "x".repeat(super::MAX_ENDPOINT_LEN + 1);

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
}

#[test]
fn validate_proxy_spec_rejects_a_malformed_direct_ingress_host() {
    let mut spec = valid_proxy_spec();
    spec.ingress.host = "https://proxy.apex.test/mcp".to_owned();

    let error = validate_proxy_spec(&spec).unwrap_err();
    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
    assert_eq!(error.message(), "Proxy hosts require a bounded host reference.");
}

#[test]
fn validate_proxy_spec_rejects_an_oversized_collection() {
    let mut spec = valid_proxy_spec();
    spec.exposed_tools = (0..=super::MAX_EXPOSED_TOOLS)
        .map(|index| ExposedTool {
            upstream_id: "portfolio-upstream".to_owned(),
            tool_name: format!("portfolio.read.{index}"),
            alias: format!("portfolio.read.{index}"),
            classification: ProxyToolClassification::Read,
        })
        .collect();

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "TOO_MANY_EXPOSED_TOOLS");
}

#[test]
fn validate_proxy_spec_rejects_an_uppercase_upstream_hash() {
    let mut spec = valid_proxy_spec();
    spec.upstreams[0].tool_catalog_hash =
        Some("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef".to_owned());

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
}

#[test]
fn proxy_revision_rejects_an_uppercase_config_hash() {
    let error = super::McpProxyRevision::new(
        proxy_id(),
        ProxyRevisionId::new(REQUEST_ID).expect("revision id"),
        valid_proxy_spec(),
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
        super::ProxyLifecycleState::Draft,
    )
    .unwrap_err();

    assert_eq!(error.code(), "INVALID_PROXY_SPEC");
}

#[test]
fn validate_proxy_spec_rejects_a_private_destination_without_an_explicit_allow_rule() {
    let mut spec = valid_proxy_spec();
    for host in [
        "10.0.0.20",
        "api.internal",
        "api.local",
        "host.docker.internal",
        "API.INTERNAL",
        "LOCALHOST",
        "Host.Docker.Internal",
    ] {
        let destination = EgressDestination::Https {
            host: host.to_owned(),
            port: 443,
            private_allowance: PrivateDestinationAllowance::Denied,
        };
        assert!(destination.requires_private_allowance());
        spec.runtime_profile.network.destinations.push(destination);
    }

    let error = validate_proxy_spec(&spec).unwrap_err();

    assert_eq!(error.code(), "PRIVATE_DESTINATION_REQUIRES_ALLOW_RULE");
    assert_eq!(
        error.message(),
        "Private network destinations require an explicit server-side allow rule."
    );
}

#[test]
fn validate_proxy_spec_accepts_a_valid_read_only_portfolio_read_configuration() {
    validate_proxy_spec(&valid_proxy_spec()).expect("valid read-only proxy spec");
}

#[test]
fn strict_wire_json_rejects_unknown_fields_before_conversion() {
    let mut wire: serde_json::Value = serde_json::from_str(valid_wire_json()).expect("wire json");
    wire["unexpected"] = serde_json::json!(true);

    let error = parse_proxy_spec_wire_json(&wire.to_string()).unwrap_err();

    assert_eq!(error.code(), "UNKNOWN_PROXY_WIRE_FIELD");
}

fn proxy_id() -> ProxyId {
    ProxyId::new(PROXY_ID).expect("valid proxy id")
}

fn valid_scope() -> ExactScope {
    ExactScope {
        workspace_id: WORKSPACE_ID.to_owned(),
        namespace_id: NAMESPACE_ID.to_owned(),
    }
}

fn valid_proxy_spec() -> ProxySpec {
    ProxySpec {
        ingress: Ingress {
            transport: ProxyTransport::StreamableHttp,
            exposure: super::ProxyExposure::Private,
            host: "proxy.apex.test".to_owned(),
            path: "/mcp".to_owned(),
            allowed_origins: vec!["https://console.apex.test".to_owned()],
            protocol_revision: "2025-11-25".to_owned(),
            inbound_authentication_required: true,
        },
        upstreams: vec![UpstreamBinding {
            upstream_id: "portfolio-upstream".to_owned(),
            display_name: "Portfolio upstream".to_owned(),
            transport: ProxyTransport::StreamableHttp,
            endpoint_or_command_ref: "https://portfolio-api.apex.test/mcp".to_owned(),
            credential_ref: Some(
                SecretRef::new("secret://vault/upstreams/portfolio-reader").expect("secret ref"),
            ),
            secret_refs: vec![],
            server_identity: "portfolio-api.apex.test".to_owned(),
            tool_catalog_hash: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        }],
        exposed_tools: vec![ExposedTool {
            upstream_id: "portfolio-upstream".to_owned(),
            tool_name: "portfolio.read".to_owned(),
            alias: "portfolio.read".to_owned(),
            classification: ProxyToolClassification::Read,
        }],
        cli_profiles: Vec::new(),
        auth_bindings: Vec::new(),
        governance_binding: GovernanceBinding {
            policy_id: "ria-read-v1".to_owned(),
            approval_mode: ApprovalMode::None,
            data_classification: DataClassification::Confidential,
            rate_limit_per_minute: 60,
            concurrency_limit: 4,
            budget_limit_per_day: 5_000,
            retention_days: 30,
        },
        runtime_profile: RuntimeProfile {
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            cpu_limit: "500m".to_owned(),
            memory_limit: "256Mi".to_owned(),
            network_policy: "default-deny".to_owned(),
            filesystem_policy: "read-only-rootfs".to_owned(),
            rootless: true,
            network: NetworkPolicy {
                destinations: vec![EgressDestination::Https {
                    host: "portfolio-api.apex.test".to_owned(),
                    port: 443,
                    private_allowance: PrivateDestinationAllowance::Denied,
                }],
            },
        },
    }
}

fn valid_cli_profile(shell: bool, timeout_ms: u32, max_output_bytes: u32) -> CliProfile {
    CliProfile {
        profile_id: "portfolio-cli".to_owned(),
        executable_ref: "image://portfolio-tools/read-portfolio".to_owned(),
        executable_digest:
            "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
        fixed_argv: vec!["--format".to_owned(), "json".to_owned()],
        argv_schema: ArgSchema {
            fields: vec![ArgSchemaField {
                name: "portfolio_id".to_owned(),
                required: true,
            }],
        },
        working_directory: "/workspace/proxy".to_owned(),
        environment_allowlist: vec!["APEX_LOG_LEVEL".to_owned()],
        secret_refs: vec![
            SecretRef::new("secret://vault/cli/portfolio-token").expect("secret ref"),
        ],
        filesystem_policy: "read-only-rootfs".to_owned(),
        network_policy: "default-deny".to_owned(),
        shell,
        timeout_ms,
        max_output_bytes,
        allowed_exit_codes: vec![0],
    }
}

fn valid_proto_spec() -> proto::McpProxySpec {
    proto::McpProxySpec {
        ingress: Some(proto::McpProxyIngress {
            transport: proto::McpProxyTransport::StreamableHttp as i32,
            exposure: proto::McpProxyExposure::Private as i32,
            host: "proxy.apex.test".to_owned(),
            path: "/mcp".to_owned(),
            allowed_origins: vec!["https://console.apex.test".to_owned()],
            protocol_revision: "2025-11-25".to_owned(),
            inbound_authentication_required: true,
        }),
        upstreams: vec![proto::McpProxyUpstreamBinding {
            upstream_id: "portfolio-upstream".to_owned(),
            display_name: "Portfolio upstream".to_owned(),
            transport: proto::McpProxyTransport::StreamableHttp as i32,
            endpoint_or_command_ref: "https://portfolio-api.apex.test/mcp".to_owned(),
            credential_ref: "secret://vault/upstreams/portfolio-reader".to_owned(),
            secret_refs: Vec::new(),
            server_identity: "portfolio-api.apex.test".to_owned(),
            tool_catalog_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }],
        exposed_tools: vec![proto::McpProxyToolExposure {
            upstream_id: "portfolio-upstream".to_owned(),
            tool_name: "portfolio.read".to_owned(),
            alias: "portfolio.read".to_owned(),
            classification: proto::McpProxyToolClassification::Read as i32,
        }],
        cli_profiles: Vec::new(),
        auth_bindings: Vec::new(),
        governance_binding: Some(proto::McpProxyGovernanceBinding {
            policy_id: "ria-read-v1".to_owned(),
            approval_mode: "none".to_owned(),
            data_classification: "confidential".to_owned(),
            rate_limit: "60/m".to_owned(),
            concurrency_limit: "4".to_owned(),
            budget: "5000/d".to_owned(),
            retention: "30d".to_owned(),
        }),
        runtime_profile: Some(proto::McpProxyRuntimeProfile {
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            cpu_limit: "500m".to_owned(),
            memory_limit: "256Mi".to_owned(),
            network_policy: "default-deny".to_owned(),
            filesystem_policy: "read-only-rootfs".to_owned(),
            rootless: true,
            egress_destinations: vec![proto::McpProxyEgressDestination {
                host: "portfolio-api.apex.test".to_owned(),
                port: 443,
                private_destination_allowance: proto::McpProxyPrivateDestinationAllowance::Denied
                    as i32,
            }],
        }),
    }
}

fn valid_wire_json() -> &'static str {
    r#"{
        "ingress": {
            "transport": 1,
            "exposure": 1,
            "host": "proxy.apex.test",
            "path": "/mcp",
            "allowed_origins": ["https://console.apex.test"],
            "protocol_revision": "2025-11-25",
            "inbound_authentication_required": true
        },
        "upstreams": [{
            "upstream_id": "portfolio-upstream",
            "display_name": "Portfolio upstream",
            "transport": 1,
            "endpoint_or_command_ref": "https://portfolio-api.apex.test/mcp",
            "credential_ref": "secret://vault/upstreams/portfolio-reader",
            "secret_refs": [],
            "server_identity": "portfolio-api.apex.test",
            "tool_catalog_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }],
        "exposed_tools": [{
            "upstream_id": "portfolio-upstream",
            "tool_name": "portfolio.read",
            "alias": "portfolio.read",
            "classification": 1
        }],
        "cli_profiles": [],
        "auth_bindings": [],
        "governance_binding": {
            "policy_id": "ria-read-v1",
            "approval_mode": "none",
            "data_classification": "confidential",
            "rate_limit": "60/m",
            "concurrency_limit": "4",
            "budget": "5000/d",
            "retention": "30d"
        },
        "runtime_profile": {
            "image_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "cpu_limit": "500m",
            "memory_limit": "256Mi",
            "network_policy": "default-deny",
            "filesystem_policy": "read-only-rootfs",
            "rootless": true,
            "egress_destinations": [{
                "host": "portfolio-api.apex.test",
                "port": 443,
                "private_destination_allowance": 1
            }]
        }
    }"#
}

fn assert_semantic_request_id(request_id: &str) {
    request_id_is_valid(request_id).expect("lowercase uuidv7 request id");
}

fn request_id_is_valid(request_id: &str) -> Result<(), &'static str> {
    if request_id.is_empty() {
        return Err("request_id is required");
    }
    // Store contract tests live under `proxy/store/tests.rs` to keep this file within the line limit.
    let uuid = Uuid::parse_str(request_id).map_err(|_| "request_id must be a uuid")?;
    if uuid.get_version_num() != 7 {
        return Err("request_id must be uuidv7");
    }
    if uuid.to_string() != request_id {
        return Err("request_id must use canonical lowercase spelling");
    }

    Ok(())
}
