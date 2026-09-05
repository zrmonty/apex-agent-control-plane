use apex_control_plane_api::{
    ApprovalMode, ArgSchema, ArgSchemaField, CliProfile, CreateProxy, DataClassification,
    EgressDestination, ExactScope, ExposedTool, GovernanceBinding, Ingress, McpProxy,
    NetworkPolicy, PrivateDestinationAllowance, ProxyExposure, ProxyId, ProxySpec,
    ProxyToolClassification, ProxyTransport, PublishRevision, RuntimeProfile, SecretRef,
    UpdateProxyDraft, UpstreamBinding,
};

pub fn request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub fn scope() -> ExactScope {
    ExactScope {
        workspace_id: "publish-workspace".into(),
        namespace_id: "publish-namespace".into(),
    }
}

pub fn create() -> CreateProxy {
    let id = request_id();
    CreateProxy {
        request_id: request_id(),
        scope: scope(),
        proxy_id: ProxyId::new(&id).unwrap(),
        display_name: "Publication capability fixture".into(),
        slug: format!("publish-{id}"),
        description: None,
        owner: None,
    }
}

pub fn edit(proxy: &McpProxy, spec: ProxySpec) -> UpdateProxyDraft {
    UpdateProxyDraft {
        request_id: request_id(),
        scope: proxy.scope.clone(),
        proxy_id: proxy.proxy_id.clone(),
        expected_revision_id: proxy.draft_revision_id.clone(),
        actor_id: "operator:publisher".into(),
        spec,
    }
}

pub fn publish(proxy: &McpProxy) -> PublishRevision {
    PublishRevision {
        request_id: request_id(),
        scope: proxy.scope.clone(),
        proxy_id: proxy.proxy_id.clone(),
        draft_revision_id: proxy.draft_revision_id.clone().unwrap(),
        expected_revision_id: proxy.active_revision_id.clone(),
        actor_id: "operator:publisher".into(),
    }
}

/// Explicit store fixture only: no fabricated deployment bindings or runtime result.
pub fn portfolio_spec() -> ProxySpec {
    ProxySpec {
        ingress: Ingress {
            transport: ProxyTransport::StreamableHttp,
            exposure: ProxyExposure::Private,
            host: "proxy.apex.test".into(),
            path: "/mcp".into(),
            allowed_origins: vec!["https://console.apex.test".into()],
            protocol_revision: "2025-11-25".into(),
            inbound_authentication_required: true,
        },
        upstreams: vec![UpstreamBinding {
            upstream_id: "portfolio-upstream".into(),
            display_name: "Portfolio".into(),
            transport: ProxyTransport::StreamableHttp,
            endpoint_or_command_ref: "https://portfolio.apex.test/mcp".into(),
            credential_ref: Some(SecretRef::new("secret://vault/portfolio-reader").unwrap()),
            secret_refs: vec![],
            server_identity: "portfolio.apex.test".into(),
            tool_catalog_hash: Some("a".repeat(64)),
        }],
        exposed_tools: vec![ExposedTool {
            upstream_id: "portfolio-upstream".into(),
            tool_name: "portfolio.read".into(),
            alias: "portfolio.read".into(),
            classification: ProxyToolClassification::Read,
        }],
        cli_profiles: vec![],
        auth_bindings: vec![],
        governance_binding: GovernanceBinding {
            policy_id: "ria-read-v1".into(),
            approval_mode: ApprovalMode::None,
            data_classification: DataClassification::Confidential,
            rate_limit_per_minute: 60,
            concurrency_limit: 4,
            budget_limit_per_day: 5_000,
            retention_days: 30,
        },
        runtime_profile: RuntimeProfile {
            image_digest: format!("sha256:{}", "b".repeat(64)),
            cpu_limit: "500m".into(),
            memory_limit: "256Mi".into(),
            network_policy: "default-deny".into(),
            filesystem_policy: "read-only-rootfs".into(),
            rootless: true,
            network: NetworkPolicy {
                destinations: vec![EgressDestination::Https {
                    host: "portfolio.apex.test".into(),
                    port: 443,
                    private_allowance: PrivateDestinationAllowance::Denied,
                }],
            },
        },
    }
}

pub fn cli_profile() -> CliProfile {
    CliProfile {
        profile_id: "portfolio-cli".into(),
        executable_ref: "image://portfolio-tools/read-portfolio".into(),
        executable_digest: format!("sha256:{}", "c".repeat(64)),
        fixed_argv: vec!["--format".into(), "json".into()],
        argv_schema: ArgSchema {
            fields: vec![ArgSchemaField {
                name: "portfolio_id".into(),
                required: true,
            }],
        },
        working_directory: "/workspace/proxy".into(),
        environment_allowlist: vec!["APEX_LOG_LEVEL".into()],
        secret_refs: vec![SecretRef::new("secret://vault/cli/portfolio-reader").unwrap()],
        filesystem_policy: "read-only-rootfs".into(),
        network_policy: "default-deny".into(),
        shell: false,
        timeout_ms: 5_000,
        max_output_bytes: 16_384,
        allowed_exit_codes: vec![0],
    }
}

pub fn unsupported_specs() -> Vec<(&'static str, ProxySpec)> {
    type Mutation = (&'static str, fn(&mut ProxySpec));
    let mutations: &[Mutation] = &[
        ("stdio_ingress", |s| {
            s.ingress.transport = ProxyTransport::Stdio
        }),
        ("protocol_revision", |s| {
            s.ingress.protocol_revision = "2025-03-26".into()
        }),
        ("unauthenticated_ingress", |s| {
            s.ingress.inbound_authentication_required = false
        }),
        ("stdio_upstream", |s| {
            s.upstreams[0].transport = ProxyTransport::Stdio
        }),
        ("unexposed_stdio_upstream", |s| {
            let mut extra = s.upstreams[0].clone();
            extra.upstream_id = "unexposed".into();
            extra.transport = ProxyTransport::Stdio;
            s.upstreams.push(extra);
        }),
        ("cli_profile", |s| s.cli_profiles.push(cli_profile())),
        ("different_upstream_tool", |s| {
            s.exposed_tools[0].tool_name = "account.read".into()
        }),
        ("different_alias", |s| {
            s.exposed_tools[0].alias = "account.read".into()
        }),
        ("business_write", |s| {
            s.exposed_tools[0].tool_name = "portfolio.write".into();
            s.exposed_tools[0].classification = ProxyToolClassification::BusinessWrite;
        }),
        ("high_impact", |s| {
            s.exposed_tools[0].tool_name = "portfolio.trade".into();
            s.exposed_tools[0].classification = ProxyToolClassification::HighImpact;
        }),
        ("additional_general_tool", |s| {
            let mut extra = s.exposed_tools[0].clone();
            extra.alias = "account.read".into();
            extra.tool_name = "account.read".into();
            s.exposed_tools.push(extra);
        }),
        ("operator_approval", |s| {
            s.governance_binding.approval_mode = ApprovalMode::Operator
        }),
        ("dual_approval", |s| {
            s.governance_binding.approval_mode = ApprovalMode::DualOperator
        }),
        ("rootful", |s| s.runtime_profile.rootless = false),
        ("writable_rootfs", |s| {
            s.runtime_profile.filesystem_policy = "writable-rootfs".into()
        }),
        ("allow_all_network", |s| {
            s.runtime_profile.network_policy = "allow-all".into()
        }),
    ];
    mutations
        .iter()
        .map(|(label, mutate)| {
            let mut spec = portfolio_spec();
            mutate(&mut spec);
            (*label, spec)
        })
        .collect()
}
