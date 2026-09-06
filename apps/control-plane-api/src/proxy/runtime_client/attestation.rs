//! Shape/integrity checks only. Registration additionally requires the actual
//! authenticated agent, protected profile/catalog compilation and fenced PG join.
use super::{ProxyError, invalid, proto};
use sha2::{Digest, Sha256};

pub(super) fn validate(
    request: &proto::RuntimeReconcileRequest,
    runtime: &proto::RuntimeObservation,
) -> Result<(), ProxyError> {
    let Some(attestation) = &runtime.launch_attestation else {
        return Ok(());
    };
    let launch = attestation.launch.as_ref().ok_or_else(invalid)?;
    let target = runtime.target.as_ref().ok_or_else(invalid)?;
    let current = request.target.as_ref().ok_or_else(invalid)?;
    let health = launch.health.as_ref().ok_or_else(invalid)?;
    if attestation.schema_version != 1
        || !apex_domain::is_lowercase_uuidv7(&attestation.installation_id)
        || !hash(&attestation.instance_proof_sha256)
        || !hash(&attestation.staged_manifest_sha256)
        || !attestation
            .image_id
            .strip_prefix("sha256:")
            .is_some_and(hash)
        || launch.schema_version != 1
        || launch.target.as_ref() != Some(target)
        || !apex_domain::is_lowercase_uuidv7(&launch.process_instance_id)
        || !hash(&launch.config_hash)
        || !hash(&launch.runtime_manifest_hash)
        || !hash(&launch.launch_context_hash)
        || (target.generation == current.generation && launch.config_hash != request.config_hash)
        || !identifier(&launch.authority_profile_ref)
        || !identifier(&launch.authority_profile_version)
        || launch.materials.len() != 13
        || health.port != 8081
        || launch.image_ref.len() > 512
        || !launch.image_ref.is_ascii()
        || !launch
            .image_ref
            .rsplit_once("@sha256:")
            .is_some_and(|(name, digest)| !name.is_empty() && hash(digest))
        || launch.launch_context_hash != launch_hash(launch)?
    {
        return Err(invalid());
    }
    let mut roles = std::collections::BTreeSet::new();
    let mut references = std::collections::BTreeSet::new();
    // Producer/catalog order is immutable and hash-significant, not role order.
    for material in &launch.materials {
        if !(1..=13).contains(&material.role)
            || !roles.insert(material.role)
            || !references.insert(&material.reference)
            || !identifier(&material.version)
            || crate::proxy::SecretRef::from_reference(&material.reference).is_err()
            || (material.role == proto::RuntimeMaterialRole::HealthToken as i32
                && material.reference != health.credential_ref)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn launch_hash(launch: &proto::RuntimeLaunchContext) -> Result<String, ProxyError> {
    let mut value = serde_json::to_value(launch).map_err(|_| invalid())?;
    value
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("launchContextHash");
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&sorted(value)).map_err(|_| invalid())?)
    ))
}
fn sorted(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(fields) => {
            let mut fields: Vec<_> = fields.into_iter().collect();
            fields.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            serde_json::Value::Object(
                fields
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sorted).collect())
        }
        scalar => scalar,
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str) -> bool {
    value.len() <= 128 && apex_domain::is_scope_identifier(value)
}
