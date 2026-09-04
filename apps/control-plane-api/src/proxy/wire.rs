use serde::Deserialize;

use super::validation::{
    bounded_endpoint, bounded_host, bounded_identifier, bounded_required_string, optional_hash,
    optional_secret_ref, parse_approval_mode, parse_data_classification, parse_positive_u32,
    parse_rate_limit, parse_retention_days,
};
use super::*;
use crate::proto;

pub fn parse_proxy_spec_wire_json(input: &str) -> Result<ProxySpec, ProxyError> {
    let wire = serde_json::from_str::<WireProxySpec>(input).map_err(|error| {
        if error.to_string().contains("unknown field") {
            ProxyError::new(
                "UNKNOWN_PROXY_WIRE_FIELD",
                "Proxy wire input contains an unknown field.",
            )
        } else {
            ProxyError::new(
                "INVALID_PROXY_WIRE",
                "Proxy wire input is not a valid structured proxy specification.",
            )
        }
    })?;
    ProxySpec::try_from(proto::McpProxySpec::from(wire))
}

pub fn validate_proxy_spec_wire_json(input: &str) -> Result<(), ProxyError> {
    parse_proxy_spec_wire_json(input).map(|_| ())
}

impl TryFrom<proto::McpProxySpec> for ProxySpec {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxySpec) -> Result<Self, Self::Error> {
        let ingress = value.ingress.ok_or_else(|| {
            ProxyError::invalid_proxy_spec("Proxy configuration requires ingress settings.")
        })?;
        let governance = value.governance_binding.ok_or_else(|| {
            ProxyError::invalid_proxy_spec("Proxy configuration requires a governance binding.")
        })?;
        let runtime = value.runtime_profile.ok_or_else(|| {
            ProxyError::invalid_proxy_spec("Proxy configuration requires a runtime profile.")
        })?;
        let spec = Self {
            ingress: Ingress::try_from(ingress)?,
            upstreams: value
                .upstreams
                .into_iter()
                .map(UpstreamBinding::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            exposed_tools: value
                .exposed_tools
                .into_iter()
                .map(ExposedTool::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            cli_profiles: value
                .cli_profiles
                .into_iter()
                .map(CliProfile::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            auth_bindings: value
                .auth_bindings
                .into_iter()
                .map(AuthBinding::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            governance_binding: GovernanceBinding::try_from(governance)?,
            runtime_profile: RuntimeProfile::try_from(runtime)?,
        };
        validate_proxy_spec(&spec)?;
        Ok(spec)
    }
}

impl TryFrom<proto::McpProxyIngress> for Ingress {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyIngress) -> Result<Self, Self::Error> {
        Ok(Self {
            transport: ProxyTransport::try_from(value.transport)?,
            exposure: ProxyExposure::try_from(value.exposure)?,
            host: bounded_host(value.host)?,
            path: bounded_required_string(value.path)?,
            allowed_origins: value
                .allowed_origins
                .into_iter()
                .map(bounded_endpoint)
                .collect::<Result<Vec<_>, _>>()?,
            protocol_revision: bounded_required_string(value.protocol_revision)?,
            inbound_authentication_required: value.inbound_authentication_required,
        })
    }
}

impl TryFrom<proto::McpProxyUpstreamBinding> for UpstreamBinding {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyUpstreamBinding) -> Result<Self, Self::Error> {
        Ok(Self {
            upstream_id: bounded_identifier(value.upstream_id)?,
            display_name: bounded_required_string(value.display_name)?,
            transport: ProxyTransport::try_from(value.transport)?,
            endpoint_or_command_ref: bounded_endpoint(value.endpoint_or_command_ref)?,
            credential_ref: optional_secret_ref(value.credential_ref)?,
            secret_refs: value
                .secret_refs
                .into_iter()
                .map(SecretRef::from_reference)
                .collect::<Result<Vec<_>, _>>()?,
            server_identity: bounded_required_string(value.server_identity)?,
            tool_catalog_hash: optional_hash(value.tool_catalog_hash)?,
        })
    }
}

impl TryFrom<proto::McpProxyToolExposure> for ExposedTool {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyToolExposure) -> Result<Self, Self::Error> {
        Ok(Self {
            upstream_id: bounded_identifier(value.upstream_id)?,
            tool_name: bounded_identifier(value.tool_name)?,
            alias: bounded_identifier(value.alias)?,
            classification: ProxyToolClassification::try_from(value.classification)?,
        })
    }
}

impl TryFrom<proto::McpProxyCliProfile> for CliProfile {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyCliProfile) -> Result<Self, Self::Error> {
        let fixed_argv = value
            .argv_template
            .into_iter()
            .map(bounded_required_string)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            profile_id: bounded_identifier(value.profile_id)?,
            executable_ref: bounded_endpoint(value.executable_ref)?,
            executable_digest: bounded_required_string(value.executable_digest)?,
            argv_schema: ArgSchema::from(&fixed_argv),
            fixed_argv,
            working_directory: bounded_endpoint(value.working_directory)?,
            environment_allowlist: value
                .environment_allowlist
                .into_iter()
                .map(bounded_identifier)
                .collect::<Result<Vec<_>, _>>()?,
            secret_refs: value
                .secret_refs
                .into_iter()
                .map(SecretRef::from_reference)
                .collect::<Result<Vec<_>, _>>()?,
            filesystem_policy: bounded_required_string(value.filesystem_policy)?,
            network_policy: bounded_required_string(value.network_policy)?,
            shell: value.shell,
            timeout_ms: value.timeout_ms,
            max_output_bytes: value.max_output_bytes,
            allowed_exit_codes: value.allowed_exit_codes,
        })
    }
}

impl ArgSchema {
    fn from(argv: &[String]) -> Self {
        let fields = argv
            .iter()
            .filter(|value| !value.starts_with('-'))
            .map(|name| ArgSchemaField {
                name: name.clone(),
                required: true,
            })
            .collect();
        Self { fields }
    }
}

impl TryFrom<proto::McpProxyAuthBinding> for AuthBinding {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyAuthBinding) -> Result<Self, Self::Error> {
        Ok(Self {
            binding_id: bounded_identifier(value.binding_id)?,
            inbound_subject: bounded_required_string(value.inbound_subject)?,
            outbound_credential_ref: optional_secret_ref(value.outbound_credential_ref)?,
            scopes: value
                .scopes
                .into_iter()
                .map(bounded_identifier)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<proto::McpProxyGovernanceBinding> for GovernanceBinding {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyGovernanceBinding) -> Result<Self, Self::Error> {
        let budget = value.budget.strip_suffix("/d").ok_or_else(|| {
            ProxyError::invalid_proxy_spec(
                "Proxy configuration requires a bounded daily budget limit.",
            )
        })?;
        Ok(Self {
            policy_id: bounded_identifier(value.policy_id)?,
            approval_mode: parse_approval_mode(&value.approval_mode)?,
            data_classification: parse_data_classification(&value.data_classification)?,
            rate_limit_per_minute: parse_rate_limit(&value.rate_limit)?,
            concurrency_limit: parse_positive_u32(&value.concurrency_limit)?,
            budget_limit_per_day: parse_positive_u32(budget)?,
            retention_days: parse_retention_days(&value.retention)?,
        })
    }
}

impl TryFrom<proto::McpProxyRuntimeProfile> for RuntimeProfile {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyRuntimeProfile) -> Result<Self, Self::Error> {
        Ok(Self {
            image_digest: bounded_required_string(value.image_digest)?,
            cpu_limit: bounded_required_string(value.cpu_limit)?,
            memory_limit: bounded_required_string(value.memory_limit)?,
            network_policy: bounded_required_string(value.network_policy)?,
            filesystem_policy: bounded_required_string(value.filesystem_policy)?,
            rootless: value.rootless,
            network: NetworkPolicy {
                destinations: value
                    .egress_destinations
                    .into_iter()
                    .map(EgressDestination::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            },
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireProxySpec {
    ingress: WireIngress,
    upstreams: Vec<WireUpstreamBinding>,
    exposed_tools: Vec<WireToolExposure>,
    cli_profiles: Vec<WireCliProfile>,
    auth_bindings: Vec<WireAuthBinding>,
    governance_binding: WireGovernanceBinding,
    runtime_profile: WireRuntimeProfile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireIngress {
    transport: i32,
    exposure: i32,
    host: String,
    path: String,
    allowed_origins: Vec<String>,
    protocol_revision: String,
    inbound_authentication_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireUpstreamBinding {
    upstream_id: String,
    display_name: String,
    transport: i32,
    endpoint_or_command_ref: String,
    credential_ref: String,
    secret_refs: Vec<String>,
    server_identity: String,
    tool_catalog_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireToolExposure {
    upstream_id: String,
    tool_name: String,
    alias: String,
    classification: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireCliProfile {
    profile_id: String,
    executable_ref: String,
    executable_digest: String,
    argv_template: Vec<String>,
    environment_allowlist: Vec<String>,
    secret_refs: Vec<String>,
    working_directory: String,
    filesystem_policy: String,
    network_policy: String,
    shell: bool,
    timeout_ms: u32,
    max_output_bytes: u32,
    allowed_exit_codes: Vec<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireAuthBinding {
    binding_id: String,
    inbound_subject: String,
    outbound_credential_ref: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireGovernanceBinding {
    policy_id: String,
    approval_mode: String,
    data_classification: String,
    rate_limit: String,
    concurrency_limit: String,
    budget: String,
    retention: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireRuntimeProfile {
    image_digest: String,
    cpu_limit: String,
    memory_limit: String,
    network_policy: String,
    filesystem_policy: String,
    rootless: bool,
    egress_destinations: Vec<WireEgressDestination>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct WireEgressDestination {
    host: String,
    port: u32,
    private_destination_allowance: i32,
}

impl From<WireProxySpec> for proto::McpProxySpec {
    fn from(value: WireProxySpec) -> Self {
        Self {
            ingress: Some(value.ingress.into()),
            upstreams: value.upstreams.into_iter().map(Into::into).collect(),
            exposed_tools: value.exposed_tools.into_iter().map(Into::into).collect(),
            cli_profiles: value.cli_profiles.into_iter().map(Into::into).collect(),
            auth_bindings: value.auth_bindings.into_iter().map(Into::into).collect(),
            governance_binding: Some(value.governance_binding.into()),
            runtime_profile: Some(value.runtime_profile.into()),
        }
    }
}

impl From<WireIngress> for proto::McpProxyIngress {
    fn from(value: WireIngress) -> Self {
        Self {
            transport: value.transport,
            exposure: value.exposure,
            host: value.host,
            path: value.path,
            allowed_origins: value.allowed_origins,
            protocol_revision: value.protocol_revision,
            inbound_authentication_required: value.inbound_authentication_required,
        }
    }
}

impl From<WireUpstreamBinding> for proto::McpProxyUpstreamBinding {
    fn from(value: WireUpstreamBinding) -> Self {
        Self {
            upstream_id: value.upstream_id,
            display_name: value.display_name,
            transport: value.transport,
            endpoint_or_command_ref: value.endpoint_or_command_ref,
            credential_ref: value.credential_ref,
            secret_refs: value.secret_refs,
            server_identity: value.server_identity,
            tool_catalog_hash: value.tool_catalog_hash,
        }
    }
}

impl From<WireToolExposure> for proto::McpProxyToolExposure {
    fn from(value: WireToolExposure) -> Self {
        Self {
            upstream_id: value.upstream_id,
            tool_name: value.tool_name,
            alias: value.alias,
            classification: value.classification,
        }
    }
}

impl From<WireCliProfile> for proto::McpProxyCliProfile {
    fn from(value: WireCliProfile) -> Self {
        Self {
            profile_id: value.profile_id,
            executable_ref: value.executable_ref,
            executable_digest: value.executable_digest,
            argv_template: value.argv_template,
            environment_allowlist: value.environment_allowlist,
            secret_refs: value.secret_refs,
            working_directory: value.working_directory,
            filesystem_policy: value.filesystem_policy,
            network_policy: value.network_policy,
            timeout_ms: value.timeout_ms,
            max_output_bytes: value.max_output_bytes,
            allowed_exit_codes: value.allowed_exit_codes,
            shell: value.shell,
        }
    }
}

impl From<WireAuthBinding> for proto::McpProxyAuthBinding {
    fn from(value: WireAuthBinding) -> Self {
        Self {
            binding_id: value.binding_id,
            inbound_subject: value.inbound_subject,
            outbound_credential_ref: value.outbound_credential_ref,
            scopes: value.scopes,
        }
    }
}

impl From<WireGovernanceBinding> for proto::McpProxyGovernanceBinding {
    fn from(value: WireGovernanceBinding) -> Self {
        Self {
            policy_id: value.policy_id,
            approval_mode: value.approval_mode,
            data_classification: value.data_classification,
            rate_limit: value.rate_limit,
            concurrency_limit: value.concurrency_limit,
            budget: value.budget,
            retention: value.retention,
        }
    }
}

impl From<WireRuntimeProfile> for proto::McpProxyRuntimeProfile {
    fn from(value: WireRuntimeProfile) -> Self {
        Self {
            image_digest: value.image_digest,
            cpu_limit: value.cpu_limit,
            memory_limit: value.memory_limit,
            network_policy: value.network_policy,
            filesystem_policy: value.filesystem_policy,
            rootless: value.rootless,
            egress_destinations: value
                .egress_destinations
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<WireEgressDestination> for proto::McpProxyEgressDestination {
    fn from(value: WireEgressDestination) -> Self {
        Self {
            host: value.host,
            port: value.port,
            private_destination_allowance: value.private_destination_allowance,
        }
    }
}
