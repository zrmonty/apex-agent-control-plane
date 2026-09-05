//! Metadata relation only; neither integrity nor authority validation.

use crate::{
    RuntimeError,
    proto::{RuntimeConfiguration, RuntimeTarget},
    shapes,
};

/// Check exact control-domain scope grammar, canonical UUIDv7 and nonzero u64s.
/// This never validates lease currency or turns a supplied fence into authority.
///
/// # Errors
/// Returns a static refusal for invalid target fields.
pub fn check_runtime_target(target: &RuntimeTarget) -> Result<(), RuntimeError> {
    if shapes::scope(&target.workspace_id)
        && shapes::scope(&target.namespace_id)
        && shapes::uuid_v7(&target.proxy_id)
        && shapes::uuid_v7(&target.revision_id)
        && target.generation != 0
        && target.fencing_token != 0
    {
        Ok(())
    } else {
        Err(RuntimeError::InvalidTarget)
    }
}

/// Check v1 metadata shape and exact target/config scope, IDs and generation.
/// Distinct hash fields need not have different values. Shaped hashes and image
/// references are not integrity/signature evidence; this does not validate the
/// complete config, recompute a manifest, consult publication or check a lease.
///
/// # Errors
/// Returns a static refusal for an invalid target or configuration binding.
pub fn check_target_configuration_binding(
    target: &RuntimeTarget,
    configuration: &RuntimeConfiguration,
) -> Result<(), RuntimeError> {
    check_runtime_target(target)?;
    if configuration.schema_version == 1
        && configuration.workspace_id == target.workspace_id
        && configuration.namespace_id == target.namespace_id
        && configuration.proxy_id == target.proxy_id
        && configuration.revision_id == target.revision_id
        && configuration.generation == target.generation
        && shapes::hex_hash(&configuration.config_hash)
        && shapes::hex_hash(&configuration.runtime_manifest_hash)
        && shapes::image_ref(&configuration.image_ref)
    {
        Ok(())
    } else {
        Err(RuntimeError::InvalidConfigurationBinding)
    }
}
