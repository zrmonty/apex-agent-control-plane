//! Lexical bounds precede TLS parsing and request allocation.

use std::net::IpAddr;

use super::{AuthorityClientConfig, AuthorityClientError, AuthorityOperation};

pub(super) fn validate(config: &AuthorityClientConfig) -> Result<(), AuthorityClientError> {
    if ![
        &config.ca_pem,
        &config.client_certificate_pem,
        &config.client_key_pem,
    ]
    .into_iter()
    .all(|pem| (1..=65_536).contains(&pem.len()))
        || ![
            &config.agent_identity_id,
            &config.enrollment_version,
            &config.host_policy_version,
        ]
        .into_iter()
        .all(|id| id.len() <= 128 && apex_domain::is_scope_identifier(id))
        || !apex_domain::is_lowercase_uuidv7(&config.installation_id)
        || !server_name(&config.tls_server_name)
        || !origin(&config.endpoint)
    {
        return Err(AuthorityClientError::InvalidConfiguration);
    }
    Ok(())
}

fn server_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return false;
    }
    if name.parse::<IpAddr>().is_ok() {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn origin(endpoint: &str) -> bool {
    if endpoint.len() > 2048
        || !endpoint.is_ascii()
        || endpoint.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'\\' | b'@' | b'?' | b'#' | b'%')
        })
    {
        return false;
    }
    let Some(authority) = endpoint.strip_prefix("https://") else {
        return false;
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains('/') {
        return false;
    }
    // Parse the original authority, not a URL-normalized path/credential/host.
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, suffix)) = ipv6.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (host, suffix)
    } else {
        match authority.split_once(':') {
            Some((host, _)) => (host, &authority[host.len()..]),
            None => (authority, ""),
        }
    };
    server_name(host)
        && (port.is_empty()
            || port.strip_prefix(':').is_some_and(|port| {
                !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit())
                    && port.parse::<u16>().is_ok_and(|value| value != 0)
            }))
}

pub(super) fn validate_operation(
    operation: &AuthorityOperation<'_>,
) -> Result<(), AuthorityClientError> {
    let target = operation.target;
    if crate::check_runtime_target(target).is_err()
        || !sql_positive(target.generation)
        || !sql_positive(target.fencing_token)
        || !apex_domain::is_lowercase_uuidv7(operation.operation_id)
        || !apex_domain::is_lowercase_uuidv7(operation.command_id)
        || !crate::shapes::hex_hash(operation.config_hash)
    {
        return Err(AuthorityClientError::InvalidInput);
    }
    Ok(())
}

pub(super) fn sql_positive(value: u64) -> bool {
    value != 0 && i64::try_from(value).is_ok()
}
