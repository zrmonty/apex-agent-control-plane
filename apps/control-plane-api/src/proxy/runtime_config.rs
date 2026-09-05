//! Pure compilation of an immutable revision and trusted deployment metadata.
//!
//! The caller must select a published revision from the authoritative store.
//! `McpProxyRevision` does not carry the store's publication flag; even a newly
//! published revision can have lifecycle state `Draft`. Compilation neither
//! proves publication nor grants deployment, approval, or runtime authority.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    ApprovalMode, McpProxyRevision, ProxyError, SecretRef, validate_mcp_proxy_revision,
    wire::proxy_spec_to_proto,
};
use crate::{ExactScope, proto};

mod network;
mod schemas;
mod validation;

/// Deployment-owned metadata, never browser input or resolved secret material.
/// The runtime agent must independently verify its catalogs, reference namespace,
/// network policy and operation fencing before installing the resulting config.
#[derive(Debug, Clone)]
pub struct RuntimeDeploymentBindings {
    pub scope: ExactScope,
    pub generation: u64,
    pub resource_url: String,
    /// Approved digest -> fully qualified, digest-pinned OCI image reference.
    pub image_catalog: BTreeMap<String, String>,
    /// Must equal the union declared by upstream, auth and CLI bindings.
    pub secret_refs: Vec<SecretRef>,
    pub tool_schemas: Vec<proto::RuntimeToolSchema>,
    /// Approved profile identifiers; profile bodies remain authority-owned.
    pub approved_output_profiles: BTreeSet<String>,
    pub network_grants: Vec<proto::RuntimeNetworkGrant>,
    pub auth: proto::RuntimeAuthentication,
    pub telemetry: proto::ProxyTelemetryPolicy,
    pub pid_limit: u32,
}

/// Compile without mutating the revision or performing I/O.
///
/// # Errors
/// Reject unsupported or incomplete security metadata and deployment shapes.
/// The supplied control hash must have its existing canonical format; the
/// trusted store owns its integrity and publication check, not this compiler.
pub fn compile_runtime_config(
    revision: &McpProxyRevision,
    bindings: &RuntimeDeploymentBindings,
) -> Result<proto::RuntimeConfiguration, ProxyError> {
    validate_mcp_proxy_revision(revision)?;
    validation::deployment(revision, bindings)?;
    network::validate(
        &revision.spec.runtime_profile.network.destinations,
        &bindings.network_grants,
    )?;
    schemas::validate(revision, bindings)?;
    let image_ref = validation::image(revision, bindings)?;
    let secret_refs = validation::secret_references(revision, &bindings.secret_refs)?;
    let (cpu_millis, memory_bytes) = validation::resource_units(
        &revision.spec.runtime_profile.cpu_limit,
        &revision.spec.runtime_profile.memory_limit,
    )?;
    let approval_mode = match revision.spec.governance_binding.approval_mode {
        ApprovalMode::None => proto::ProxyApprovalMode::None,
        ApprovalMode::Operator => proto::ProxyApprovalMode::Operator,
        ApprovalMode::DualOperator => proto::ProxyApprovalMode::DualOperator,
    };
    // Explicit fields keep generated contract additions visible to the compiler.
    // The existing wire conversion retains every control-spec field and array.
    let mut config = proto::RuntimeConfiguration {
        schema_version: 1,
        workspace_id: bindings.scope.workspace_id.clone(),
        namespace_id: bindings.scope.namespace_id.clone(),
        proxy_id: revision.proxy_id.to_string(),
        revision_id: revision.revision_id.to_string(),
        config_hash: revision.config_hash.clone(),
        generation: bindings.generation,
        resource_url: bindings.resource_url.clone(),
        spec: Some(proxy_spec_to_proto(&revision.spec)),
        tool_schemas: bindings.tool_schemas.clone(),
        network_grants: bindings.network_grants.clone(),
        auth: Some(bindings.auth.clone()),
        telemetry: Some(bindings.telemetry),
        approval_mode: approval_mode.into(),
        runtime_manifest_hash: String::new(),
        image_ref,
        cpu_millis,
        memory_bytes,
        pid_limit: bindings.pid_limit,
        secret_refs,
    };
    config.runtime_manifest_hash = runtime_manifest_hash(&config)?;
    let json = serde_json::to_vec(&config).map_err(|_| encoding_error())?;
    // Use the same bounded generated JSON entry point as the eventual consumer.
    // This rejects excessive output size/field count without emitting a manifest.
    crate::contract_json::decode_management_json::<proto::RuntimeConfiguration>(&json)
        .map_err(|_| invalid())?;
    Ok(config)
}

/// SHA-256 of recursively key-sorted generated ProtoJSON, with array order
/// preserved and `runtimeManifestHash` omitted. The control hash is retained.
///
/// # Errors
/// The coordinated API returns `Result<String, ProxyError>`: generated enum
/// drift or serialization failure returns a static error, never a panic,
/// sentinel, or a substitute digest of an empty/default configuration.
pub fn runtime_manifest_hash(config: &proto::RuntimeConfiguration) -> Result<String, ProxyError> {
    let mut json = serde_json::to_value(config).map_err(|_| encoding_error())?;
    let object = json.as_object_mut().ok_or_else(encoding_error)?;
    object.remove("runtimeManifestHash");
    let canonical = serde_json::to_vec(&sorted(json)).map_err(|_| encoding_error())?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut fields: Vec<_> = fields.into_iter().collect();
            fields.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            Value::Object(
                fields
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

fn encoding_error() -> ProxyError {
    ProxyError::new(
        "RUNTIME_MANIFEST_ENCODING_FAILED",
        "Runtime manifest cannot be encoded.",
    )
}

fn invalid() -> ProxyError {
    ProxyError::new(
        "INVALID_RUNTIME_CONFIGURATION",
        "Runtime configuration has missing, invalid, or unsupported security settings.",
    )
}

fn require(condition: bool) -> Result<(), ProxyError> {
    if condition { Ok(()) } else { Err(invalid()) }
}
