use std::net::IpAddr;

use uuid::Uuid;

use crate::{ExactScope, proto};

mod validation;

pub use validation::validate_proxy_spec;
use validation::{
    bounded_endpoint, bounded_identifier, bounded_required_string, is_lowercase_uuidv7,
    is_scope_identifier, optional_hash, optional_secret_ref, parse_approval_mode,
    parse_budget_limit, parse_data_classification, parse_positive_u32, parse_rate_limit,
    parse_retention_days,
};

#[cfg(test)]
mod tests;

pub(super) const MAX_IDENTIFIER_LEN: usize = 128;
pub(super) const MAX_ENDPOINT_LEN: usize = 512;

macro_rules! bounded_string {
    ($name:ident, $max_len:expr, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ProxyError> {
                let value = value.into();
                if value.is_empty() || value.len() > $max_len {
                    return Err(ProxyError::invalid_proxy_spec($message));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

bounded_string!(
    SecretRef,
    MAX_ENDPOINT_LEN,
    "Proxy secret references must be bounded non-empty references."
);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyId(Uuid);

impl ProxyId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProxyError> {
        parse_uuid_v7(value.as_ref()).map(Self).map_err(|_| {
            ProxyError::invalid_proxy_draft("Proxy identifiers must be lowercase UUIDv7 values.")
        })
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyRevisionId(Uuid);

impl ProxyRevisionId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProxyError> {
        parse_uuid_v7(value.as_ref()).map(Self).map_err(|_| {
            ProxyError::invalid_proxy_spec(
                "Proxy revision identifiers must be lowercase UUIDv7 values.",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyLifecycleState {
    Draft,
    Validating,
    AwaitingApproval,
    Provisioning,
    Ready,
    Degraded,
    Paused,
    Failed,
    Retiring,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTransport {
    StreamableHttp,
    Stdio,
}

impl TryFrom<i32> for ProxyTransport {
    type Error = ProxyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match proto::McpProxyTransport::try_from(value).ok() {
            Some(proto::McpProxyTransport::StreamableHttp) => Ok(Self::StreamableHttp),
            Some(proto::McpProxyTransport::Stdio) => Ok(Self::Stdio),
            _ => Err(ProxyError::unknown_transport()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyToolClassification {
    Read,
    BusinessWrite,
    HighImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    None,
    Operator,
    DualOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateDestinationAllowance {
    Denied,
    Allowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDestination {
    Https {
        host: String,
        port: u16,
        private_allowance: PrivateDestinationAllowance,
    },
}

impl EgressDestination {
    pub fn requires_private_allowance(&self) -> bool {
        match self {
            Self::Https { host, .. } => is_private_host(host),
        }
    }

    pub fn private_allowance(&self) -> PrivateDestinationAllowance {
        match self {
            Self::Https {
                private_allowance, ..
            } => *private_allowance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub destinations: Vec<EgressDestination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub image_digest: String,
    pub network: NetworkPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamBinding {
    pub upstream_id: String,
    pub display_name: String,
    pub transport: ProxyTransport,
    pub endpoint_or_command_ref: String,
    pub credential_ref: Option<SecretRef>,
    pub secret_refs: Vec<SecretRef>,
    pub server_identity: String,
    pub tool_catalog_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedTool {
    pub upstream_id: String,
    pub tool_name: String,
    pub alias: String,
    pub classification: ProxyToolClassification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSchemaField {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSchema {
    pub fields: Vec<ArgSchemaField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliProfile {
    pub profile_id: String,
    pub executable_ref: String,
    pub executable_digest: String,
    pub fixed_argv: Vec<String>,
    pub argv_schema: ArgSchema,
    pub working_directory: String,
    pub environment_allowlist: Vec<String>,
    pub secret_refs: Vec<SecretRef>,
    pub shell: bool,
    pub timeout_ms: u32,
    pub max_output_bytes: u32,
    pub allowed_exit_codes: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceBinding {
    pub policy_id: String,
    pub approval_mode: ApprovalMode,
    pub data_classification: DataClassification,
    pub rate_limit_per_minute: u32,
    pub concurrency_limit: u32,
    pub budget_limit_per_day: u32,
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySpec {
    pub ingress_transport: ProxyTransport,
    pub upstreams: Vec<UpstreamBinding>,
    pub exposed_tools: Vec<ExposedTool>,
    pub cli_profiles: Vec<CliProfile>,
    pub governance_binding: GovernanceBinding,
    pub runtime_profile: RuntimeProfile,
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

        let transport = ProxyTransport::try_from(ingress.transport)?;
        let upstreams = value
            .upstreams
            .into_iter()
            .map(UpstreamBinding::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let default_upstream = upstreams
            .first()
            .map(|binding| binding.upstream_id.clone())
            .ok_or_else(|| {
                ProxyError::invalid_proxy_spec(
                    "Proxy configuration requires at least one upstream binding.",
                )
            })?;

        let exposed_tools = value
            .exposed_tools
            .into_iter()
            .map(|tool_name| ExposedTool {
                upstream_id: default_upstream.clone(),
                alias: tool_name.clone(),
                tool_name,
                classification: ProxyToolClassification::Read,
            })
            .collect();

        Ok(Self {
            ingress_transport: transport,
            upstreams,
            exposed_tools,
            cli_profiles: value
                .cli_profiles
                .into_iter()
                .map(CliProfile::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            governance_binding: GovernanceBinding::try_from(governance)?,
            runtime_profile: RuntimeProfile::try_from(runtime)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDraft {
    pub proxy_id: ProxyId,
    pub scope: ExactScope,
    pub display_name: String,
    pub slug: String,
    pub spec: ProxySpec,
}

impl ProxyDraft {
    pub fn new(
        proxy_id: ProxyId,
        scope: ExactScope,
        display_name: impl Into<String>,
        slug: impl Into<String>,
        spec: ProxySpec,
    ) -> Result<Self, ProxyError> {
        if !is_scope_identifier(&scope.workspace_id) || !is_scope_identifier(&scope.namespace_id) {
            return Err(ProxyError::invalid_proxy_scope());
        }

        let display_name = display_name.into();
        if display_name.is_empty() || display_name.len() > MAX_ENDPOINT_LEN {
            return Err(ProxyError::invalid_proxy_draft(
                "Proxy drafts require a non-empty bounded display name.",
            ));
        }

        let slug = slug.into();
        if !is_valid_slug(&slug) {
            return Err(ProxyError::invalid_proxy_draft(
                "Proxy drafts require a non-empty bounded slug.",
            ));
        }

        validate_proxy_spec(&spec)?;

        Ok(Self {
            proxy_id,
            scope,
            display_name,
            slug,
            spec,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxyRevision {
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub spec: ProxySpec,
    pub config_hash: String,
    pub lifecycle_state: ProxyLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyError {
    code: &'static str,
    message: &'static str,
}

impl ProxyError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    pub fn invalid_proxy_draft(message: &'static str) -> Self {
        Self::new("INVALID_PROXY_DRAFT", message)
    }

    pub fn invalid_proxy_scope() -> Self {
        Self::new(
            "INVALID_PROXY_SCOPE",
            "Proxy drafts require an exact workspace and namespace scope.",
        )
    }

    pub fn invalid_proxy_spec(message: &'static str) -> Self {
        Self::new("INVALID_PROXY_SPEC", message)
    }

    pub fn unknown_transport() -> Self {
        Self::new(
            "UNKNOWN_PROXY_TRANSPORT",
            "Proxy configuration uses an unsupported transport.",
        )
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProxyError {}

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
                .map(SecretRef::new)
                .collect::<Result<Vec<_>, _>>()?,
            server_identity: bounded_required_string(value.server_identity)?,
            tool_catalog_hash: optional_hash(value.tool_catalog_hash)?,
        })
    }
}

impl TryFrom<proto::McpProxyCliProfile> for CliProfile {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyCliProfile) -> Result<Self, Self::Error> {
        let argv_template = value.argv_template;
        Ok(Self {
            profile_id: bounded_identifier(value.profile_id)?,
            executable_ref: bounded_endpoint(value.executable_ref)?,
            executable_digest: bounded_required_string(value.executable_digest)?,
            fixed_argv: argv_template
                .iter()
                .cloned()
                .map(bounded_required_string)
                .collect::<Result<Vec<_>, _>>()?,
            argv_schema: ArgSchema::from(argv_template),
            working_directory: bounded_endpoint(value.working_directory)?,
            environment_allowlist: value
                .environment_allowlist
                .into_iter()
                .map(bounded_identifier)
                .collect::<Result<Vec<_>, _>>()?,
            secret_refs: value
                .secret_refs
                .into_iter()
                .map(SecretRef::new)
                .collect::<Result<Vec<_>, _>>()?,
            shell: false,
            timeout_ms: value.timeout_ms,
            max_output_bytes: value.max_output_bytes,
            allowed_exit_codes: value.allowed_exit_codes,
        })
    }
}

impl ArgSchema {
    fn from(argv_template: Vec<String>) -> Self {
        let fields = argv_template
            .into_iter()
            .filter(|value| !value.starts_with('-'))
            .map(|name| ArgSchemaField {
                name,
                required: true,
            })
            .collect();
        Self { fields }
    }
}

impl TryFrom<proto::McpProxyGovernanceBinding> for GovernanceBinding {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyGovernanceBinding) -> Result<Self, Self::Error> {
        Ok(Self {
            policy_id: bounded_identifier(value.policy_id)?,
            approval_mode: parse_approval_mode(&value.approval_mode)?,
            data_classification: parse_data_classification(&value.data_classification)?,
            rate_limit_per_minute: parse_rate_limit(&value.rate_limit)?,
            concurrency_limit: parse_positive_u32(&value.concurrency_limit)?,
            budget_limit_per_day: parse_budget_limit(&value.budget)?,
            retention_days: parse_retention_days(&value.retention)?,
        })
    }
}

impl TryFrom<proto::McpProxyRuntimeProfile> for RuntimeProfile {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyRuntimeProfile) -> Result<Self, Self::Error> {
        if value.image_digest.is_empty() {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy runtime profiles require an immutable image digest.",
            ));
        }

        Ok(Self {
            image_digest: value.image_digest,
            network: NetworkPolicy {
                destinations: Vec::new(),
            },
        })
    }
}

fn parse_uuid_v7(value: &str) -> Result<Uuid, ()> {
    if !is_lowercase_uuidv7(value) {
        return Err(());
    }
    Uuid::parse_str(value).map_err(|_| ())
}

fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_private_host(value: &str) -> bool {
    value
        .parse::<IpAddr>()
        .map_or(false, |address| match address {
            IpAddr::V4(ipv4) => {
                ipv4.is_private()
                    || ipv4.is_loopback()
                    || ipv4.is_link_local()
                    || ipv4.is_broadcast()
                    || ipv4.is_documentation()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unique_local() || ipv6.is_unicast_link_local()
            }
        })
}
