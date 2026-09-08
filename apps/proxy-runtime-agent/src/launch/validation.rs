//! Eager lexical checks and exact deployment relations; no effect authority.

use super::{
    LaunchError,
    catalog::{Document, Profile},
};
use crate::{proto, shapes};
use std::collections::BTreeSet;

pub(super) fn document(document: &Document) -> Result<(), LaunchError> {
    let invalid = LaunchError::InvalidCatalog;
    if document.schema_version != 1
        || !shapes::version(&document.version)
        || !sql_positive(document.valid_from_unix_us)
        || !sql_positive(document.expires_at_unix_us)
        || document.valid_from_unix_us >= document.expires_at_unix_us
        || !(1..=32).contains(&document.profiles.len())
    {
        return Err(invalid);
    }
    let mut selectors = BTreeSet::new();
    for entry in &document.profiles {
        let p = &entry.0;
        profile(p)?;
        if !selectors.insert((
            &p.installation_id,
            &p.workspace_id,
            &p.namespace_id,
            &p.proxy_id,
            &p.revision_id,
            &p.host_policy_version,
            &p.deployment_bindings_version,
            &p.config_hash,
        )) {
            return Err(invalid);
        }
    }
    Ok(())
}

fn profile(p: &Profile) -> Result<(), LaunchError> {
    let invalid = LaunchError::InvalidCatalog;
    if !shapes::uuid_v7(&p.installation_id)
        || !shapes::uuid_v7(&p.proxy_id)
        || !shapes::uuid_v7(&p.revision_id)
        || !shapes::scope(&p.workspace_id)
        || !shapes::scope(&p.namespace_id)
        || !shapes::version(&p.host_policy_version)
        || !shapes::version(&p.deployment_bindings_version)
        || !shapes::version(&p.authority_profile_ref)
        || !shapes::version(&p.authority_profile_version)
        || !shapes::hex_hash(&p.config_hash)
        || !image_id(&p.image_catalog_id)
        || p.materials.len() != 13
    {
        return Err(invalid);
    }
    let mut roles = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for entry in &p.materials {
        let m = &entry.0;
        if !(1..=13).contains(&i32::from(m.role.0))
            || !shapes::secret_reference(&m.reference)
            || !shapes::version(&m.version)
            || !source_name(&m.source_name)
            || !roles.insert(i32::from(m.role.0))
            || !references.insert(&m.reference)
            || !sources.insert(&m.source_name)
        {
            return Err(invalid);
        }
    }
    Ok(())
}

fn image_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && !value.contains("..")
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn source_name(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(super) fn sql_positive(value: u64) -> bool {
    value != 0 && i64::try_from(value).is_ok()
}

pub(super) fn configuration(
    authority: &proto::RuntimeAuthoritySnapshot,
    configuration: &proto::RuntimeConfiguration,
) -> Result<(), LaunchError> {
    let invalid = LaunchError::InvalidConfiguration;
    let target = authority.target.as_ref().ok_or(invalid)?;
    if crate::check_target_configuration_binding(target, configuration).is_err()
        || !sql_positive(target.generation)
        || !sql_positive(target.fencing_token)
        || authority.config_hash != configuration.config_hash
    {
        return Err(invalid);
    }
    // Bound serialization before allocating a JSON tree for manifest hashing.
    super::hash::bounded_json(configuration, 262_144).map_err(|_| invalid)?;
    if crate::runtime_manifest_hash(configuration).map_err(|_| invalid)?
        != configuration.runtime_manifest_hash
    {
        return Err(invalid);
    }
    Ok(())
}
