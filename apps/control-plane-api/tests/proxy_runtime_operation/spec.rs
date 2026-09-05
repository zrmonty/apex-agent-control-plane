use apex_control_plane_api::*;

pub(super) fn supported_spec() -> ProxySpec {
    ProxySpec {
        ingress: Ingress {
            transport: ProxyTransport::StreamableHttp,
            exposure: ProxyExposure::Private,
            host: "gateway.example.test".into(),
            path: "/mcp".into(),
            allowed_origins: vec!["https://operator.example.test".into()],
            protocol_revision: "2025-11-25".into(),
            inbound_authentication_required: true,
        },
        upstreams: vec![UpstreamBinding {
            upstream_id: "portfolio".into(),
            display_name: "Portfolio".into(),
            transport: ProxyTransport::StreamableHttp,
            endpoint_or_command_ref: "https://portfolio.example.test/mcp".into(),
            credential_ref: Some(SecretRef::new("secret://SNAPSHOT_CANARY/upstream").unwrap()),
            secret_refs: vec![],
            server_identity: "portfolio.example.test".into(),
            tool_catalog_hash: Some("a".repeat(64)),
        }],
        exposed_tools: vec![ExposedTool {
            upstream_id: "portfolio".into(),
            tool_name: "portfolio.read".into(),
            alias: "portfolio.read".into(),
            classification: ProxyToolClassification::Read,
        }],
        cli_profiles: vec![],
        auth_bindings: vec![],
        governance_binding: GovernanceBinding {
            policy_id: "portfolio-policy".into(),
            approval_mode: ApprovalMode::None,
            data_classification: DataClassification::Internal,
            rate_limit_per_minute: 60,
            concurrency_limit: 2,
            budget_limit_per_day: 100,
            retention_days: 7,
        },
        runtime_profile: RuntimeProfile {
            image_digest: format!("sha256:{}", "a".repeat(64)),
            cpu_limit: "500m".into(),
            memory_limit: "256Mi".into(),
            network_policy: "default-deny".into(),
            filesystem_policy: "read-only-rootfs".into(),
            rootless: true,
            network: NetworkPolicy {
                destinations: vec![EgressDestination::Https {
                    host: "portfolio.example.test".into(),
                    port: 443,
                    private_allowance: PrivateDestinationAllowance::Denied,
                }],
            },
        },
    }
}
