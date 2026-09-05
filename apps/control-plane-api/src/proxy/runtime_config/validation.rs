use std::collections::BTreeSet;

use super::{RuntimeDeploymentBindings, invalid, require};
use crate::proxy::{
    McpProxyRevision, ProxyError, ProxyTransport, SecretRef, validation::is_scope_identifier,
};

pub(super) fn deployment(
    revision: &McpProxyRevision,
    b: &RuntimeDeploymentBindings,
) -> Result<(), ProxyError> {
    require(
        is_scope_identifier(&b.scope.workspace_id) && is_scope_identifier(&b.scope.namespace_id),
    )?;
    require(b.generation > 0 && (16..=1024).contains(&b.pid_limit))?;
    let ingress = &revision.spec.ingress;
    let profile = &revision.spec.runtime_profile;
    // CLI/stdio need the later agent's approved executable and confinement
    // contract. Do not silently serialize an unsupported executable shape.
    require(
        ingress.transport == ProxyTransport::StreamableHttp
            && ingress.protocol_revision == "2025-11-25"
            && ingress.inbound_authentication_required
            && profile.rootless
            && profile.network_policy == "default-deny"
            && profile.filesystem_policy == "read-only-rootfs"
            && revision.spec.cli_profiles.is_empty(),
    )?;
    let resource = https_url(&b.resource_url)?;
    require(
        resource.as_str() == b.resource_url
            && resource.host_str() == Some(ingress.host.as_str())
            && resource.path() == ingress.path
            && resource.port_or_known_default() == Some(443)
            && b.auth.audience == b.resource_url,
    )?;
    for origin in &ingress.allowed_origins {
        let url = https_url(origin)?;
        require(url.path() == "/")?;
    }
    https_url(&b.auth.issuer)?;
    https_url(&b.auth.jwks_uri)?;
    reference(&b.auth.workload_identity_ref, "identity://")?;
    require(!b.auth.required_scopes.is_empty() && b.auth.required_scopes.len() <= 64)?;
    let mut scopes = BTreeSet::new();
    for scope in &b.auth.required_scopes {
        require(identifier(scope) && scopes.insert(scope))?;
    }
    for upstream in &revision.spec.upstreams {
        require(
            upstream.transport == ProxyTransport::StreamableHttp
                && upstream.tool_catalog_hash.as_deref().is_some_and(hex_hash),
        )?;
        let url = https_url(&upstream.endpoint_or_command_ref)?;
        require(b.network_grants.iter().any(|grant| {
            url.host_str() == Some(grant.host.as_str())
                && url.port_or_known_default().map(u32::from) == Some(grant.port)
        }))?;
    }
    let t = &b.telemetry;
    require(
        (1..=1_000_000).contains(&t.full_trace_sample_per_million)
            && (1..=32).contains(&t.max_stages)
            && (1..=65_536).contains(&t.max_summary_bytes)
            && (1..=128).contains(&t.max_spans)
            && (1..=64).contains(&t.max_attributes_per_span)
            && (1..=8_388_608).contains(&t.max_export_queue_bytes),
    )
}

pub(super) fn secret_references(
    revision: &McpProxyRevision,
    bindings: &[SecretRef],
) -> Result<Vec<String>, ProxyError> {
    let spec = &revision.spec;
    let declared: BTreeSet<_> = spec
        .upstreams
        .iter()
        .flat_map(|u| u.credential_ref.iter().chain(&u.secret_refs))
        .chain(
            spec.auth_bindings
                .iter()
                .flat_map(|b| b.outbound_credential_ref.iter()),
        )
        .chain(spec.cli_profiles.iter().flat_map(|p| &p.secret_refs))
        .map(SecretRef::as_str)
        .collect();
    require(bindings.len() <= 4096)?;
    let supplied: BTreeSet<_> = bindings.iter().map(SecretRef::as_str).collect();
    require(supplied.len() == bindings.len() && supplied == declared)?;
    for value in &declared {
        reference(value, "secret://")?;
    }
    Ok(declared.into_iter().map(str::to_owned).collect())
}

pub(super) fn image(
    revision: &McpProxyRevision,
    b: &RuntimeDeploymentBindings,
) -> Result<String, ProxyError> {
    require(!b.image_catalog.is_empty() && b.image_catalog.len() <= 256)?;
    let digest = &revision.spec.runtime_profile.image_digest;
    let image = b.image_catalog.get(digest).ok_or_else(invalid)?;
    require(image.len() <= 512)?;
    let (name, selected_digest) = image.split_once('@').ok_or_else(invalid)?;
    require(selected_digest == digest)?;
    let (registry, repository) = name.split_once('/').ok_or_else(invalid)?;
    let registry_url = https_url(&format!("https://{registry}/"))?;
    require(
        registry.contains('.')
            && registry_url.path() == "/"
            && registry_url.origin().ascii_serialization() == format!("https://{registry}"),
    )?;
    require(repository.split('/').all(|part| {
        !part.is_empty()
            && !part.contains("..")
            && part
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && part.bytes().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
            })
    }))?;
    Ok(image.clone())
}

pub(super) fn resource_units(cpu: &str, memory: &str) -> Result<(u32, u64), ProxyError> {
    let (cpu_digits, cpu_scale) = cpu.strip_suffix('m').map_or((cpu, 1000), |s| (s, 1));
    let cpu_millis = decimal(cpu_digits)?
        .checked_mul(cpu_scale)
        .ok_or_else(invalid)?;
    require((1..=4000).contains(&cpu_millis))?;
    let (memory_digits, scale) = if let Some(digits) = memory.strip_suffix("Ki") {
        (digits, 1024)
    } else if let Some(digits) = memory.strip_suffix("Mi") {
        (digits, 1_048_576)
    } else if let Some(digits) = memory.strip_suffix("Gi") {
        (digits, 1_073_741_824)
    } else {
        (memory, 1)
    };
    let memory_bytes = decimal(memory_digits)?
        .checked_mul(scale)
        .ok_or_else(invalid)?;
    require((16_777_216..=2_147_483_648).contains(&memory_bytes))?;
    Ok((
        u32::try_from(cpu_millis).map_err(|_| invalid())?,
        memory_bytes,
    ))
}

fn decimal(value: &str) -> Result<u64, ProxyError> {
    require(!value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()))?;
    value.parse().map_err(|_| invalid())
}

pub(super) fn https_url(value: &str) -> Result<reqwest::Url, ProxyError> {
    require(
        !value.is_empty()
            && value.len() <= 512
            && !value
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\\'),
    )?;
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    require(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
    )?;
    Ok(url)
}

pub(super) fn reference(value: &str, prefix: &str) -> Result<(), ProxyError> {
    let tail = value.strip_prefix(prefix).ok_or_else(invalid)?;
    require(
        value.len() <= 512
            && !tail.is_empty()
            && tail
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && tail
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && tail.bytes().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b'-')
            }),
    )
}

pub(super) fn identifier(value: &str) -> bool {
    value.len() <= 128 && is_scope_identifier(value)
}

pub(super) fn hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
