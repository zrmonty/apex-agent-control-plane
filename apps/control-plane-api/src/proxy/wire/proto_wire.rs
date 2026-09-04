use super::*;
use crate::proto;

pub(crate) fn proxy_spec_to_proto(value: &ProxySpec) -> proto::McpProxySpec {
    proto::McpProxySpec {
        ingress: Some(proto::McpProxyIngress {
            transport: transport_to_proto(value.ingress.transport),
            exposure: exposure_to_proto(value.ingress.exposure),
            host: value.ingress.host.clone(),
            path: value.ingress.path.clone(),
            allowed_origins: value.ingress.allowed_origins.clone(),
            protocol_revision: value.ingress.protocol_revision.clone(),
            inbound_authentication_required: value.ingress.inbound_authentication_required,
        }),
        upstreams: value
            .upstreams
            .iter()
            .map(|upstream| proto::McpProxyUpstreamBinding {
                upstream_id: upstream.upstream_id.clone(),
                display_name: upstream.display_name.clone(),
                transport: transport_to_proto(upstream.transport),
                endpoint_or_command_ref: upstream.endpoint_or_command_ref.clone(),
                credential_ref: upstream
                    .credential_ref
                    .as_ref()
                    .map(SecretRef::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                secret_refs: upstream
                    .secret_refs
                    .iter()
                    .map(|secret| secret.as_str().to_owned())
                    .collect(),
                server_identity: upstream.server_identity.clone(),
                tool_catalog_hash: upstream.tool_catalog_hash.clone().unwrap_or_default(),
            })
            .collect(),
        exposed_tools: value
            .exposed_tools
            .iter()
            .map(|tool| proto::McpProxyToolExposure {
                upstream_id: tool.upstream_id.clone(),
                tool_name: tool.tool_name.clone(),
                alias: tool.alias.clone(),
                classification: classification_to_proto(tool.classification),
            })
            .collect(),
        cli_profiles: value
            .cli_profiles
            .iter()
            .map(|profile| proto::McpProxyCliProfile {
                profile_id: profile.profile_id.clone(),
                executable_ref: profile.executable_ref.clone(),
                executable_digest: profile.executable_digest.clone(),
                argv_template: profile.fixed_argv.clone(),
                environment_allowlist: profile.environment_allowlist.clone(),
                secret_refs: profile
                    .secret_refs
                    .iter()
                    .map(|secret| secret.as_str().to_owned())
                    .collect(),
                working_directory: profile.working_directory.clone(),
                filesystem_policy: profile.filesystem_policy.clone(),
                network_policy: profile.network_policy.clone(),
                timeout_ms: profile.timeout_ms,
                max_output_bytes: profile.max_output_bytes,
                allowed_exit_codes: profile.allowed_exit_codes.clone(),
                shell: profile.shell,
                argv_schema: Some(proto::McpProxyArgSchema {
                    fields: profile
                        .argv_schema
                        .fields
                        .iter()
                        .map(|field| proto::McpProxyArgSchemaField {
                            name: field.name.clone(),
                            required: field.required,
                        })
                        .collect(),
                }),
            })
            .collect(),
        auth_bindings: value
            .auth_bindings
            .iter()
            .map(|binding| proto::McpProxyAuthBinding {
                binding_id: binding.binding_id.clone(),
                inbound_subject: binding.inbound_subject.clone(),
                outbound_credential_ref: binding
                    .outbound_credential_ref
                    .as_ref()
                    .map(SecretRef::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                scopes: binding.scopes.clone(),
            })
            .collect(),
        governance_binding: Some(proto::McpProxyGovernanceBinding {
            policy_id: value.governance_binding.policy_id.clone(),
            approval_mode: approval_mode_to_proto(value.governance_binding.approval_mode),
            data_classification: classification_name(value.governance_binding.data_classification),
            rate_limit: format!("{}/m", value.governance_binding.rate_limit_per_minute),
            concurrency_limit: value.governance_binding.concurrency_limit.to_string(),
            budget: format!("{}/d", value.governance_binding.budget_limit_per_day),
            retention: format!("{}d", value.governance_binding.retention_days),
        }),
        runtime_profile: Some(proto::McpProxyRuntimeProfile {
            image_digest: value.runtime_profile.image_digest.clone(),
            cpu_limit: value.runtime_profile.cpu_limit.clone(),
            memory_limit: value.runtime_profile.memory_limit.clone(),
            network_policy: value.runtime_profile.network_policy.clone(),
            filesystem_policy: value.runtime_profile.filesystem_policy.clone(),
            rootless: value.runtime_profile.rootless,
            egress_destinations: value
                .runtime_profile
                .network
                .destinations
                .iter()
                .map(|destination| match destination {
                    EgressDestination::Https {
                        host,
                        port,
                        private_allowance,
                    } => proto::McpProxyEgressDestination {
                        host: host.clone(),
                        port: u32::from(*port),
                        private_destination_allowance: allowance_to_proto(*private_allowance),
                    },
                })
                .collect(),
        }),
    }
}

fn transport_to_proto(value: ProxyTransport) -> i32 {
    match value {
        ProxyTransport::StreamableHttp => 1,
        ProxyTransport::Stdio => 2,
    }
}

fn exposure_to_proto(value: ProxyExposure) -> i32 {
    match value {
        ProxyExposure::Private => 1,
        ProxyExposure::External => 2,
    }
}

fn classification_to_proto(value: ProxyToolClassification) -> i32 {
    match value {
        ProxyToolClassification::Read => 1,
        ProxyToolClassification::BusinessWrite => 2,
        ProxyToolClassification::HighImpact => 3,
    }
}

fn approval_mode_to_proto(value: ApprovalMode) -> String {
    match value {
        ApprovalMode::None => "none",
        ApprovalMode::Operator => "operator",
        ApprovalMode::DualOperator => "dual-operator",
    }
    .to_owned()
}

fn classification_name(value: DataClassification) -> String {
    match value {
        DataClassification::Public => "public",
        DataClassification::Internal => "internal",
        DataClassification::Confidential => "confidential",
        DataClassification::Restricted => "restricted",
    }
    .to_owned()
}

fn allowance_to_proto(value: PrivateDestinationAllowance) -> i32 {
    match value {
        PrivateDestinationAllowance::Denied => 1,
        PrivateDestinationAllowance::Allowed => 2,
    }
}
