use crate::proxy::{
    ApprovalMode, DataClassification, MAX_ENDPOINT_LEN, MAX_IDENTIFIER_LEN,
    PrivateDestinationAllowance, ProxyError, ProxySpec, ProxyToolClassification, SecretRef,
};

pub fn validate_proxy_spec(spec: &ProxySpec) -> Result<(), ProxyError> {
    if spec.upstreams.is_empty() {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires at least one upstream binding.",
        ));
    }

    for upstream in &spec.upstreams {
        if upstream.credential_ref.is_none() {
            return Err(ProxyError::new(
                "MISSING_CREDENTIAL_REFERENCE",
                "Each upstream binding must reference a stored credential.",
            ));
        }
    }

    if spec.exposed_tools.is_empty() {
        return Err(ProxyError::new(
            "EMPTY_TOOL_ALLOWLIST",
            "Proxy revisions must explicitly expose at least one tool.",
        ));
    }

    for tool in &spec.exposed_tools {
        let upstream_exists = spec
            .upstreams
            .iter()
            .any(|upstream| upstream.upstream_id == tool.upstream_id);
        if !upstream_exists {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy tool exposure must bind to a declared upstream.",
            ));
        }
        if tool.tool_name == "portfolio.read"
            && tool.classification != ProxyToolClassification::Read
        {
            return Err(ProxyError::invalid_proxy_spec(
                "The portfolio.read acceptance slice must remain read-only.",
            ));
        }
    }

    for profile in &spec.cli_profiles {
        if profile.shell {
            return Err(ProxyError::new(
                "CLI_SHELL_DISABLED_REQUIRED",
                "CLI profiles must disable shell interpretation.",
            ));
        }
        if profile.timeout_ms == 0 {
            return Err(ProxyError::new(
                "CLI_TIMEOUT_REQUIRED",
                "CLI profiles require a bounded timeout.",
            ));
        }
        if profile.max_output_bytes == 0 {
            return Err(ProxyError::new(
                "CLI_MAX_OUTPUT_REQUIRED",
                "CLI profiles require a bounded output limit.",
            ));
        }
    }

    if spec.governance_binding.policy_id.is_empty() {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires a policy reference.",
        ));
    }
    if spec.runtime_profile.image_digest.is_empty() {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy runtime profiles require an immutable image digest.",
        ));
    }

    for destination in &spec.runtime_profile.network.destinations {
        if destination.requires_private_allowance()
            && destination.private_allowance() != PrivateDestinationAllowance::Allowed
        {
            return Err(ProxyError::new(
                "PRIVATE_DESTINATION_REQUIRES_ALLOW_RULE",
                "Private network destinations require an explicit server-side allow rule.",
            ));
        }
    }

    Ok(())
}

pub(super) fn bounded_identifier(value: String) -> Result<String, ProxyError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LEN || !is_scope_identifier(&value) {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration contains an invalid bounded identifier.",
        ));
    }
    Ok(value)
}

pub(super) fn bounded_required_string(value: String) -> Result<String, ProxyError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_LEN {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration contains an unbounded string field.",
        ));
    }
    Ok(value)
}

pub(super) fn bounded_endpoint(value: String) -> Result<String, ProxyError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_LEN {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires bounded endpoint references.",
        ));
    }
    Ok(value)
}

pub(super) fn optional_secret_ref(value: String) -> Result<Option<SecretRef>, ProxyError> {
    if value.is_empty() {
        Ok(None)
    } else {
        SecretRef::new(value).map(Some)
    }
}

pub(super) fn optional_hash(value: String) -> Result<Option<String>, ProxyError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(Some(value.to_ascii_lowercase()));
    }
    Err(ProxyError::invalid_proxy_spec(
        "Proxy configuration requires lowercase SHA-256 hashes when provided.",
    ))
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
    value
        .strip_suffix("/m")
        .ok_or_else(|| {
            ProxyError::invalid_proxy_spec(
                "Proxy configuration requires a bounded per-minute rate limit.",
            )
        })?
        .parse()
        .map_err(|_| {
            ProxyError::invalid_proxy_spec(
                "Proxy configuration requires a bounded per-minute rate limit.",
            )
        })
}

pub(super) fn parse_positive_u32(value: &str) -> Result<u32, ProxyError> {
    let parsed = value.parse().map_err(|_| {
        ProxyError::invalid_proxy_spec("Proxy configuration requires a positive bounded limit.")
    })?;
    if parsed == 0 {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy configuration requires a positive bounded limit.",
        ));
    }
    Ok(parsed)
}

pub(super) fn parse_budget_limit(value: &str) -> Result<u32, ProxyError> {
    value
        .strip_suffix("/d")
        .ok_or_else(|| {
            ProxyError::invalid_proxy_spec(
                "Proxy configuration requires a bounded daily budget limit.",
            )
        })?
        .parse()
        .map_err(|_| {
            ProxyError::invalid_proxy_spec(
                "Proxy configuration requires a bounded daily budget limit.",
            )
        })
}

pub(super) fn parse_retention_days(value: &str) -> Result<u32, ProxyError> {
    value
        .strip_suffix('d')
        .ok_or_else(|| {
            ProxyError::invalid_proxy_spec("Proxy configuration requires bounded retention days.")
        })?
        .parse()
        .map_err(|_| {
            ProxyError::invalid_proxy_spec("Proxy configuration requires bounded retention days.")
        })
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
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
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
