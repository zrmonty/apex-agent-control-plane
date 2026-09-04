use std::collections::HashSet;

use crate::proxy::{
    ApprovalMode, AuthBinding, CliProfile, DataClassification, EgressDestination, ExposedTool,
    GovernanceBinding, Ingress, MAX_ALLOWED_ORIGINS, MAX_ARG_SCHEMA_FIELDS, MAX_ARGV, MAX_AUTH_BINDINGS,
    MAX_CLI_PROFILES, MAX_COLLECTION_LIMIT, MAX_CONFIG_HASH_LEN, MAX_DESTINATIONS, MAX_ENDPOINT_LEN,
    MAX_ENVIRONMENT_ENTRIES, MAX_EXIT_CODES, MAX_EXPOSED_TOOLS, MAX_IDENTIFIER_LEN, MAX_OUTPUT_BYTES,
    MAX_SCOPES, MAX_SECRET_REFS, MAX_STRING_LEN, MAX_TIMEOUT_MS, MAX_UPSTREAMS, McpProxyRevision,
    PrivateDestinationAllowance, ProxyError, ProxySpec, ProxyToolClassification, RuntimeProfile, SecretRef,
    UpstreamBinding,
};

pub fn validate_proxy_spec(spec: &ProxySpec) -> Result<(), ProxyError> {
    validate_ingress(&spec.ingress)?;
    validate_collection(
        "upstreams",
        spec.upstreams.len(),
        MAX_UPSTREAMS,
        "TOO_MANY_UPSTREAMS",
    )?;
    validate_collection(
        "exposed tools",
        spec.exposed_tools.len(),
        MAX_EXPOSED_TOOLS,
        "TOO_MANY_EXPOSED_TOOLS",
    )?;
    validate_collection(
        "CLI profiles",
        spec.cli_profiles.len(),
        MAX_CLI_PROFILES,
        "TOO_MANY_CLI_PROFILES",
    )?;
    validate_collection(
        "auth bindings",
        spec.auth_bindings.len(),
        MAX_AUTH_BINDINGS,
        "TOO_MANY_AUTH_BINDINGS",
    )?;

    if spec.upstreams.is_empty() {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires at least one upstream binding.",
        ));
    }
    if spec.exposed_tools.is_empty() {
        return Err(ProxyError::new(
            "EMPTY_TOOL_ALLOWLIST",
            "Proxy revisions must explicitly expose at least one tool.",
        ));
    }

    let mut upstream_ids = HashSet::new();
    for upstream in &spec.upstreams {
        validate_upstream(upstream)?;
        if !upstream_ids.insert(upstream.upstream_id.as_str()) {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy upstream identifiers must be unique.",
            ));
        }
    }

    let mut aliases = HashSet::new();
    for tool in &spec.exposed_tools {
        validate_exposed_tool(tool, &upstream_ids)?;
        if !aliases.insert(tool.alias.as_str()) {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy tool aliases must be unique.",
            ));
        }
    }

    for profile in &spec.cli_profiles {
        validate_cli_profile(profile)?;
    }
    for binding in &spec.auth_bindings {
        validate_auth_binding(binding)?;
    }
    validate_governance(&spec.governance_binding)?;
    validate_runtime(&spec.runtime_profile)?;
    Ok(())
}
pub fn validate_mcp_proxy_revision(revision: &McpProxyRevision) -> Result<(), ProxyError> {
    validate_proxy_spec(&revision.spec)?;
    validate_hex_hash(
        &revision.config_hash,
        "Proxy revisions require a lowercase SHA-256 config hash.",
    )
}
fn validate_ingress(ingress: &Ingress) -> Result<(), ProxyError> {
    validate_host(&ingress.host)?;
    validate_required_string(&ingress.path, "Proxy ingress path")?;
    validate_collection(
        "allowed origins",
        ingress.allowed_origins.len(),
        MAX_ALLOWED_ORIGINS,
        "TOO_MANY_ALLOWED_ORIGINS",
    )?;
    for origin in &ingress.allowed_origins {
        validate_endpoint(origin, "Proxy allowed origin")?;
    }
    validate_required_string(&ingress.protocol_revision, "Proxy protocol revision")
}
fn validate_upstream(upstream: &UpstreamBinding) -> Result<(), ProxyError> {
    validate_identifier(&upstream.upstream_id, "Proxy upstream identifier")?;
    validate_required_string(&upstream.display_name, "Proxy upstream display name")?;
    validate_endpoint(
        &upstream.endpoint_or_command_ref,
        "Proxy upstream endpoint or command reference",
    )?;
    let credential = upstream.credential_ref.as_ref().ok_or_else(|| {
        ProxyError::new(
            "MISSING_CREDENTIAL_REFERENCE",
            "Each upstream binding must reference a stored credential.",
        )
    })?;
    validate_secret_ref(credential)?;
    validate_collection(
        "upstream secret references",
        upstream.secret_refs.len(),
        MAX_SECRET_REFS,
        "TOO_MANY_SECRET_REFS",
    )?;
    for secret_ref in &upstream.secret_refs {
        validate_secret_ref(secret_ref)?;
    }
    validate_required_string(&upstream.server_identity, "Proxy upstream server identity")?;
    if let Some(hash) = &upstream.tool_catalog_hash {
        validate_hex_hash(hash, "Proxy upstream hashes must be lowercase SHA-256 values.")?;
    }
    Ok(())
}
fn validate_exposed_tool(tool: &ExposedTool, upstream_ids: &HashSet<&str>) -> Result<(), ProxyError> {
    validate_identifier(&tool.upstream_id, "Proxy tool upstream identifier")?;
    validate_identifier(&tool.tool_name, "Proxy tool name")?;
    validate_identifier(&tool.alias, "Proxy tool alias")?;
    if !upstream_ids.contains(tool.upstream_id.as_str()) {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy tool exposure must bind to a declared upstream.",
        ));
    }
    if tool.tool_name == "portfolio.read" && tool.classification != ProxyToolClassification::Read {
        return Err(ProxyError::invalid_proxy_spec(
            "The portfolio.read acceptance slice must remain read-only.",
        ));
    }
    Ok(())
}
fn validate_cli_profile(profile: &CliProfile) -> Result<(), ProxyError> {
    validate_identifier(&profile.profile_id, "CLI profile identifier")?;
    validate_endpoint(&profile.executable_ref, "CLI executable reference")?;
    validate_sha256_digest(
        &profile.executable_digest,
        "CLI executable digests must be lowercase SHA-256 values.",
    )?;
    validate_collection(
        "CLI argv entries",
        profile.fixed_argv.len(),
        MAX_ARGV,
        "TOO_MANY_CLI_ARGV_ENTRIES",
    )?;
    for argument in &profile.fixed_argv {
        validate_required_string(argument, "CLI fixed argv entry")?;
    }
    validate_collection(
        "CLI argv schema fields",
        profile.argv_schema.fields.len(),
        MAX_ARG_SCHEMA_FIELDS,
        "TOO_MANY_CLI_ARG_SCHEMA_FIELDS",
    )?;
    for field in &profile.argv_schema.fields {
        validate_identifier(&field.name, "CLI argv schema field")?;
    }
    validate_endpoint(&profile.working_directory, "CLI working directory")?;
    validate_collection(
        "CLI environment entries",
        profile.environment_allowlist.len(),
        MAX_ENVIRONMENT_ENTRIES,
        "TOO_MANY_CLI_ENVIRONMENT_ENTRIES",
    )?;
    for environment in &profile.environment_allowlist {
        validate_identifier(environment, "CLI environment entry")?;
    }
    validate_collection(
        "CLI secret references",
        profile.secret_refs.len(),
        MAX_SECRET_REFS,
        "TOO_MANY_SECRET_REFS",
    )?;
    for secret_ref in &profile.secret_refs {
        validate_secret_ref(secret_ref)?;
    }
    validate_required_string(&profile.filesystem_policy, "CLI filesystem policy")?;
    validate_required_string(&profile.network_policy, "CLI network policy")?;
    if profile.shell {
        return Err(ProxyError::new(
            "CLI_SHELL_DISABLED_REQUIRED",
            "CLI profiles must disable shell interpretation.",
        ));
    }
    if profile.timeout_ms == 0 || profile.timeout_ms > MAX_TIMEOUT_MS {
        return Err(ProxyError::new(
            "CLI_TIMEOUT_REQUIRED",
            "CLI profiles require a bounded timeout.",
        ));
    }
    if profile.max_output_bytes == 0 || profile.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ProxyError::new(
            "CLI_MAX_OUTPUT_REQUIRED",
            "CLI profiles require a bounded output limit.",
        ));
    }
    validate_collection(
        "CLI exit codes",
        profile.allowed_exit_codes.len(),
        MAX_EXIT_CODES,
        "TOO_MANY_CLI_EXIT_CODES",
    )?;
    for code in &profile.allowed_exit_codes {
        if !(-128..=255).contains(code) {
            return Err(ProxyError::invalid_proxy_spec(
                "CLI allowed exit codes must be bounded process exit codes.",
            ));
        }
    }
    Ok(())
}

fn validate_auth_binding(binding: &AuthBinding) -> Result<(), ProxyError> {
    validate_identifier(&binding.binding_id, "Auth binding identifier")?;
    validate_required_string(&binding.inbound_subject, "Auth inbound subject")?;
    let credential = binding.outbound_credential_ref.as_ref().ok_or_else(|| {
        ProxyError::new(
            "MISSING_CREDENTIAL_REFERENCE",
            "Auth bindings must reference a stored outbound credential.",
        )
    })?;
    validate_secret_ref(credential)?;
    validate_collection(
        "auth scopes",
        binding.scopes.len(),
        MAX_SCOPES,
        "TOO_MANY_AUTH_SCOPES",
    )?;
    for scope in &binding.scopes {
        validate_identifier(scope, "Auth scope")?;
    }
    Ok(())
}

fn validate_governance(governance: &GovernanceBinding) -> Result<(), ProxyError> {
    validate_identifier(&governance.policy_id, "Governance policy identifier")?;
    if governance.rate_limit_per_minute == 0 || governance.rate_limit_per_minute > MAX_COLLECTION_LIMIT {
        return Err(ProxyError::invalid_proxy_spec(
            "Governance rate limits must be positive and bounded.",
        ));
    }
    if governance.concurrency_limit == 0 || governance.concurrency_limit > MAX_COLLECTION_LIMIT {
        return Err(ProxyError::invalid_proxy_spec(
            "Governance concurrency limits must be positive and bounded.",
        ));
    }
    if governance.budget_limit_per_day == 0 || governance.budget_limit_per_day > MAX_COLLECTION_LIMIT {
        return Err(ProxyError::invalid_proxy_spec(
            "Governance budget limits must be positive and bounded.",
        ));
    }
    if governance.retention_days == 0 || governance.retention_days > 3650 {
        return Err(ProxyError::invalid_proxy_spec(
            "Governance retention must be positive and bounded.",
        ));
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeProfile) -> Result<(), ProxyError> {
    validate_sha256_digest(
        &runtime.image_digest,
        "Proxy runtime images require lowercase SHA-256 digests.",
    )?;
    validate_required_string(&runtime.cpu_limit, "Proxy runtime CPU limit")?;
    validate_required_string(&runtime.memory_limit, "Proxy runtime memory limit")?;
    validate_required_string(&runtime.network_policy, "Proxy runtime network policy")?;
    validate_required_string(&runtime.filesystem_policy, "Proxy runtime filesystem policy")?;
    validate_collection(
        "egress destinations",
        runtime.network.destinations.len(),
        MAX_DESTINATIONS,
        "TOO_MANY_EGRESS_DESTINATIONS",
    )?;
    if runtime.network.destinations.is_empty() {
        return Err(ProxyError::new(
            "MISSING_EGRESS_DESTINATIONS",
            "Proxy runtime profiles require explicit egress destinations.",
        ));
    }
    for destination in &runtime.network.destinations {
        validate_destination(destination)?;
    }
    Ok(())
}

fn validate_destination(destination: &EgressDestination) -> Result<(), ProxyError> {
    match destination {
        EgressDestination::Https {
            host,
            port,
            private_allowance,
        } => {
            validate_host(host)?;
            if *port == 0 {
                return Err(ProxyError::invalid_proxy_spec(
                    "Proxy egress destinations require a valid port.",
                ));
            }
            if destination.requires_private_allowance()
                && *private_allowance != PrivateDestinationAllowance::Allowed
            {
                return Err(ProxyError::new(
                    "PRIVATE_DESTINATION_REQUIRES_ALLOW_RULE",
                    "Private network destinations require an explicit server-side allow rule.",
                ));
            }
        }
    }
    Ok(())
}

fn validate_secret_ref(secret_ref: &SecretRef) -> Result<(), ProxyError> {
    if secret_ref.as_str().len() > MAX_ENDPOINT_LEN
        || !secret_ref.as_str().starts_with("secret://")
        || secret_ref.as_str().chars().any(char::is_control)
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy credentials must use bounded SecretRef references.",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<(), ProxyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || value.chars().any(char::is_control)
        || !is_scope_identifier(value)
    {
        return Err(ProxyError::invalid_proxy_spec(field_error(field)));
    }
    Ok(())
}

fn validate_required_string(value: &str, field: &str) -> Result<(), ProxyError> {
    if value.is_empty() || value.len() > MAX_STRING_LEN || value.chars().any(char::is_control) {
        return Err(ProxyError::invalid_proxy_spec(field_error(field)));
    }
    Ok(())
}

fn validate_endpoint(value: &str, field: &str) -> Result<(), ProxyError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_LEN || value.chars().any(char::is_control) {
        return Err(ProxyError::invalid_proxy_spec(field_error(field)));
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<(), ProxyError> {
    let normalized = value.trim_matches(['[', ']']);
    if normalized.is_empty()
        || value.len() > MAX_ENDPOINT_LEN
        || normalized.contains("://")
        || normalized.contains('/')
        || normalized.chars().any(char::is_whitespace)
        || (!normalized.parse::<std::net::IpAddr>().is_ok() && !is_dns_hostname(normalized))
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy hosts require a bounded host reference.",
        ));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str, message: &'static str) -> Result<(), ProxyError> {
    let valid_prefix = value.starts_with("sha256:");
    let digest = value.strip_prefix("sha256:").unwrap_or_default();
    if !valid_prefix
        || digest.len() != MAX_CONFIG_HASH_LEN
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProxyError::invalid_proxy_spec(message));
    }
    Ok(())
}

fn validate_hex_hash(value: &str, message: &'static str) -> Result<(), ProxyError> {
    if value.len() != MAX_CONFIG_HASH_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProxyError::invalid_proxy_spec(message));
    }
    Ok(())
}

fn validate_collection(
    name: &str,
    actual: usize,
    maximum: usize,
    code: &'static str,
) -> Result<(), ProxyError> {
    if actual > maximum {
        return Err(ProxyError::new(
            code,
            match name {
                "upstreams" => "Proxy specifications contain too many upstream bindings.",
                "exposed tools" => "Proxy specifications contain too many exposed tools.",
                "CLI profiles" => "Proxy specifications contain too many CLI profiles.",
                "auth bindings" => "Proxy specifications contain too many auth bindings.",
                _ => "Proxy specification collection exceeds its bounded size.",
            },
        ));
    }
    Ok(())
}

fn field_error(_field: &str) -> &'static str {
    "Proxy configuration contains an empty, invalid, or unbounded string field."
}

pub(super) fn bounded_identifier(value: String) -> Result<String, ProxyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || value.chars().any(char::is_control)
        || !is_scope_identifier(&value)
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration contains an invalid bounded identifier.",
        ));
    }
    Ok(value)
}

pub(super) fn bounded_required_string(value: String) -> Result<String, ProxyError> {
    if value.is_empty() || value.len() > MAX_STRING_LEN || value.chars().any(char::is_control) {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration contains an unbounded string field.",
        ));
    }
    Ok(value)
}

pub(super) fn bounded_endpoint(value: String) -> Result<String, ProxyError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_LEN || value.chars().any(char::is_control) {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires bounded endpoint references.",
        ));
    }
    Ok(value)
}

pub(super) fn bounded_host(value: String) -> Result<String, ProxyError> {
    validate_host(&value)?;
    Ok(value)
}

pub(super) fn optional_secret_ref(value: String) -> Result<Option<SecretRef>, ProxyError> {
    if value.is_empty() {
        Ok(None)
    } else {
        SecretRef::from_reference(value).map(Some)
    }
}

pub(super) fn optional_hash(value: String) -> Result<Option<String>, ProxyError> {
    if value.is_empty() {
        return Ok(None);
    }
    validate_hex_hash(
        &value,
        "Proxy configuration requires lowercase SHA-256 hashes when provided.",
    )?;
    Ok(Some(value))
}

pub(super) fn parse_approval_mode(value: &str) -> Result<ApprovalMode, ProxyError> {
    match value {
        "none" => Ok(ApprovalMode::None),
        "operator" => Ok(ApprovalMode::Operator),
        "dual-operator" => Ok(ApprovalMode::DualOperator),
        _ => Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration uses an unsupported approval mode.",
        )),
    }
}

pub(super) fn parse_data_classification(value: &str) -> Result<DataClassification, ProxyError> {
    match value {
        "public" => Ok(DataClassification::Public),
        "internal" => Ok(DataClassification::Internal),
        "confidential" => Ok(DataClassification::Confidential),
        "restricted" => Ok(DataClassification::Restricted),
        _ => Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration uses an unsupported data classification.",
        )),
    }
}

pub(super) fn parse_rate_limit(value: &str) -> Result<u32, ProxyError> {
    let value = value.strip_suffix("/m").ok_or_else(|| {
        ProxyError::invalid_proxy_spec("Proxy configuration requires a bounded per-minute rate limit.")
    })?;
    parse_positive_u32(value)
}

pub(super) fn parse_positive_u32(value: &str) -> Result<u32, ProxyError> {
    let parsed = value.parse::<u32>().map_err(|_| {
        ProxyError::invalid_proxy_spec("Proxy configuration requires a positive bounded limit.")
    })?;
    if parsed == 0 || parsed > MAX_COLLECTION_LIMIT {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires a positive bounded limit.",
        ));
    }
    Ok(parsed)
}

pub(super) fn parse_retention_days(value: &str) -> Result<u32, ProxyError> {
    let days = value.strip_suffix('d').ok_or_else(|| {
        ProxyError::invalid_proxy_spec("Proxy configuration requires bounded retention days.")
    })?;
    let days = days.parse::<u32>().map_err(|_| {
        ProxyError::invalid_proxy_spec("Proxy configuration requires bounded retention days.")
    })?;
    if days == 0 || days > 3650 {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires bounded retention days.",
        ));
    }
    Ok(days)
}

pub(super) fn is_lowercase_uuidv7(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().get(8) == Some(&b'-')
        && value.as_bytes().get(13) == Some(&b'-')
        && value.as_bytes().get(18) == Some(&b'-')
        && value.as_bytes().get(23) == Some(&b'-')
        && value.as_bytes().get(14) == Some(&b'7')
        && matches!(value.as_bytes().get(19), Some(b'8' | b'9' | b'a' | b'b'))
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        })
}

fn is_dns_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}

pub(super) fn is_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
