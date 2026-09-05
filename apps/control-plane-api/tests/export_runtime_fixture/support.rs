use apex_control_plane_api::{
    ExactScope, McpProxyRevision, ProxyId, ProxyLifecycleState, ProxyRevisionId, ProxySpec,
    RuntimeDeploymentBindings, SecretRef, proto,
};
use std::path::PathBuf;

// Independently calculated from the existing runtime golden using Node crypto:
// SHA256(compact JSON with recursively sorted object keys, hash field omitted).
pub const RUNTIME_HASH: &str = "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da";

pub fn fixture() -> (
    McpProxyRevision,
    RuntimeDeploymentBindings,
    proto::RuntimeConfiguration,
) {
    let control: proto::McpProxyRevision = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/control-revision.json"
    ))
    .unwrap();
    let runtime: proto::RuntimeConfiguration = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    ))
    .unwrap();
    let mut revision = McpProxyRevision::new(
        ProxyId::new(&control.proxy_id).unwrap(),
        ProxyRevisionId::new(&control.revision_id).unwrap(),
        ProxySpec::try_from(control.spec.unwrap()).unwrap(),
        control.config_hash,
        ProxyLifecycleState::Ready,
    )
    .unwrap();
    revision.created_at = control.created_at;
    revision.created_by = control.created_by;
    let bindings = RuntimeDeploymentBindings {
        scope: ExactScope {
            workspace_id: runtime.workspace_id.clone(),
            namespace_id: runtime.namespace_id.clone(),
        },
        generation: runtime.generation,
        resource_url: runtime.resource_url.clone(),
        image_catalog: [(
            revision.spec.runtime_profile.image_digest.clone(),
            runtime.image_ref.clone(),
        )]
        .into(),
        secret_refs: runtime
            .secret_refs
            .iter()
            .map(|reference| SecretRef::new(reference).unwrap())
            .collect(),
        tool_schemas: runtime.tool_schemas.clone(),
        approved_output_profiles: ["portfolio-read-v1".into()].into(),
        network_grants: runtime.network_grants.clone(),
        auth: runtime.auth.clone().unwrap(),
        telemetry: runtime.telemetry.unwrap(),
        pid_limit: runtime.pid_limit,
    };
    (revision, bindings, runtime)
}

/// Extend the independent generated golden, then parse its control spec to the
/// real domain. The expected spec never comes from the compiler's wire helper.
pub fn rich_fixture() -> (
    McpProxyRevision,
    RuntimeDeploymentBindings,
    proto::McpProxySpec,
) {
    let (mut revision, mut bindings, runtime) = fixture();
    let mut spec = runtime.spec.unwrap();
    spec.ingress
        .as_mut()
        .unwrap()
        .allowed_origins
        .push("https://ops.apex.test".into());
    spec.upstreams[0]
        .secret_refs
        .push("secret://vault/upstreams/shared-ca".into());
    let mut upstream = spec.upstreams[0].clone();
    upstream.upstream_id = "quotes".into();
    upstream.display_name = "Quotes upstream".into();
    upstream.endpoint_or_command_ref = "https://quotes.apex.test/mcp".into();
    upstream.server_identity = "quotes.apex.test".into();
    upstream.credential_ref = "secret://vault/upstreams/quotes-reader".into();
    spec.upstreams.push(upstream);
    spec.exposed_tools.push(proto::McpProxyToolExposure {
        upstream_id: "quotes".into(),
        tool_name: "quotes.read".into(),
        alias: "market.quotes".into(),
        classification: 1,
    });
    spec.auth_bindings.push(proto::McpProxyAuthBinding {
        binding_id: "operator-portfolio".into(),
        inbound_subject: "agent-portfolio".into(),
        outbound_credential_ref: "secret://vault/auth/outbound".into(),
        scopes: vec!["mcp:tools".into(), "portfolio:read".into()],
    });
    spec.governance_binding.as_mut().unwrap().approval_mode = "dual-operator".into();
    spec.runtime_profile
        .as_mut()
        .unwrap()
        .egress_destinations
        .push(proto::McpProxyEgressDestination {
            host: "quotes.apex.test".into(),
            port: 443,
            private_destination_allowance: 1,
        });
    bindings.network_grants.push(proto::RuntimeNetworkGrant {
        grant_id: "quotes-https".into(),
        host: "quotes.apex.test".into(),
        port: 443,
        approved_cidrs: vec!["8.8.8.8/32".into(), "8.8.4.4/32".into()],
        private_destination: false,
    });
    let mut schema = bindings.tool_schemas[0].clone();
    schema.upstream_id = "quotes".into();
    schema.tool_name = "quotes.read".into();
    schema.output_profile_id = "quotes-read-v1".into();
    bindings.tool_schemas.push(schema);
    bindings
        .approved_output_profiles
        .insert("quotes-read-v1".into());
    for reference in [
        "secret://vault/upstreams/shared-ca",
        "secret://vault/upstreams/quotes-reader",
        "secret://vault/auth/outbound",
    ] {
        bindings
            .secret_refs
            .push(SecretRef::new(reference).unwrap());
    }
    revision.spec = ProxySpec::try_from(spec.clone()).unwrap();
    (revision, bindings, spec)
}

pub fn export(config: &proto::RuntimeConfiguration) -> PathBuf {
    use std::io::Write;
    let directory =
        std::env::temp_dir().join(format!("apex-runtime-fixture-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("runtime-revision.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(config).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    path
}
