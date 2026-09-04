use std::net::IpAddr;

use uuid::Uuid;

use crate::{ExactScope, proto};

mod validation;
mod wire;

use validation::{bounded_host, bounded_required_string, is_lowercase_uuidv7, is_scope_identifier};
pub use validation::{validate_mcp_proxy_revision, validate_proxy_spec};
pub use wire::{parse_proxy_spec_wire_json, validate_proxy_spec_wire_json};

#[cfg(test)]
mod tests;

pub(super) const MAX_IDENTIFIER_LEN: usize = 128;
pub(super) const MAX_ENDPOINT_LEN: usize = 512;
pub(super) const MAX_STRING_LEN: usize = 512;
pub(super) const MAX_COLLECTION_LIMIT: u32 = 1_000_000;
pub(super) const MAX_UPSTREAMS: usize = 64;
pub(super) const MAX_EXPOSED_TOOLS: usize = 256;
pub(super) const MAX_CLI_PROFILES: usize = 32;
pub(super) const MAX_AUTH_BINDINGS: usize = 32;
pub(super) const MAX_DESTINATIONS: usize = 64;
pub(super) const MAX_ALLOWED_ORIGINS: usize = 32;
pub(super) const MAX_SCOPES: usize = 64;
pub(super) const MAX_SECRET_REFS: usize = 32;
pub(super) const MAX_ARGV: usize = 64;
pub(super) const MAX_ARG_SCHEMA_FIELDS: usize = 64;
pub(super) const MAX_ENVIRONMENT_ENTRIES: usize = 64;
pub(super) const MAX_EXIT_CODES: usize = 32;
pub(super) const MAX_TIMEOUT_MS: u32 = 300_000;
pub(super) const MAX_OUTPUT_BYTES: u32 = 16 * 1024 * 1024;
pub(super) const MAX_CONFIG_HASH_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(value: impl Into<String>) -> Result<Self, ProxyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_LEN
            || value.chars().any(char::is_control)
            || !value.starts_with("secret://")
        {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy secret references must be bounded SecretRef references.",
            ));
        }
        Ok(Self(value))
    }

    pub fn from_reference(value: impl Into<String>) -> Result<Self, ProxyError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
pub enum ProxyExposure {
    Private,
    External,
}

impl TryFrom<i32> for ProxyExposure {
    type Error = ProxyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match proto::McpProxyExposure::try_from(value).ok() {
            Some(proto::McpProxyExposure::Private) => Ok(Self::Private),
            Some(proto::McpProxyExposure::External) => Ok(Self::External),
            _ => Err(ProxyError::invalid_proxy_spec(
                "Proxy configuration uses an unsupported exposure mode.",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyToolClassification {
    Read,
    BusinessWrite,
    HighImpact,
}

impl TryFrom<i32> for ProxyToolClassification {
    type Error = ProxyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match proto::McpProxyToolClassification::try_from(value).ok() {
            Some(proto::McpProxyToolClassification::Read) => Ok(Self::Read),
            Some(proto::McpProxyToolClassification::BusinessWrite) => Ok(Self::BusinessWrite),
            Some(proto::McpProxyToolClassification::HighImpact) => Ok(Self::HighImpact),
            _ => Err(ProxyError::invalid_proxy_spec(
                "Proxy tool exposure uses an unsupported classification.",
            )),
        }
    }
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

impl TryFrom<i32> for PrivateDestinationAllowance {
    type Error = ProxyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match proto::McpProxyPrivateDestinationAllowance::try_from(value).ok() {
            Some(proto::McpProxyPrivateDestinationAllowance::Denied) => Ok(Self::Denied),
            Some(proto::McpProxyPrivateDestinationAllowance::Allowed) => Ok(Self::Allowed),
            _ => Err(ProxyError::invalid_proxy_spec(
                "Proxy egress destinations require an explicit private-destination allowance.",
            )),
        }
    }
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

impl TryFrom<proto::McpProxyEgressDestination> for EgressDestination {
    type Error = ProxyError;

    fn try_from(value: proto::McpProxyEgressDestination) -> Result<Self, Self::Error> {
        let port = u16::try_from(value.port).map_err(|_| {
            ProxyError::invalid_proxy_spec("Proxy egress destinations require a valid port.")
        })?;
        Ok(Self::Https {
            host: bounded_host(value.host)?,
            port,
            private_allowance: PrivateDestinationAllowance::try_from(
                value.private_destination_allowance,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub destinations: Vec<EgressDestination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    pub transport: ProxyTransport,
    pub exposure: ProxyExposure,
    pub host: String,
    pub path: String,
    pub allowed_origins: Vec<String>,
    pub protocol_revision: String,
    pub inbound_authentication_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub image_digest: String,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub network_policy: String,
    pub filesystem_policy: String,
    pub rootless: bool,
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
    pub filesystem_policy: String,
    pub network_policy: String,
    pub shell: bool,
    pub timeout_ms: u32,
    pub max_output_bytes: u32,
    pub allowed_exit_codes: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBinding {
    pub binding_id: String,
    pub inbound_subject: String,
    pub outbound_credential_ref: Option<SecretRef>,
    pub scopes: Vec<String>,
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
    pub ingress: Ingress,
    pub upstreams: Vec<UpstreamBinding>,
    pub exposed_tools: Vec<ExposedTool>,
    pub cli_profiles: Vec<CliProfile>,
    pub auth_bindings: Vec<AuthBinding>,
    pub governance_binding: GovernanceBinding,
    pub runtime_profile: RuntimeProfile,
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

        let display_name = bounded_required_string(display_name.into())?;
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

impl McpProxyRevision {
    pub fn new(
        proxy_id: ProxyId,
        revision_id: ProxyRevisionId,
        spec: ProxySpec,
        config_hash: impl Into<String>,
        lifecycle_state: ProxyLifecycleState,
    ) -> Result<Self, ProxyError> {
        let revision = Self {
            proxy_id,
            revision_id,
            spec,
            config_hash: config_hash.into(),
            lifecycle_state,
        };
        validate_mcp_proxy_revision(&revision)?;
        Ok(revision)
    }
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
    let normalized = value.trim_matches(['[', ']']);
    let lowercase_host = normalized.to_ascii_lowercase();
    if matches!(lowercase_host.as_str(), "localhost" | "host.docker.internal")
        || lowercase_host.ends_with(".internal")
        || lowercase_host.ends_with(".local")
    {
        return true;
    }
    normalized
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
