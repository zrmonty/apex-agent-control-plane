//! Pure protected enrollment join; no authentication, fence adoption or serving.
use super::{Entry, Refused, digest, identifier};
use crate::{proto, proxy::store::DeploymentRegistration};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Write},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchEnrollment {
    config_hash: String,
    host_policy_version: String,
    deployment_bindings_version: String,
    image_ref: String,
    image_id: String,
    materials: Vec<Material>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    role: String,
    reference: String,
    version: String,
}

impl LaunchEnrollment {
    pub(super) fn validate(&self) -> Result<(), Refused> {
        digest(&self.config_hash)?;
        if !identifier(&self.host_policy_version)
            || !identifier(&self.deployment_bindings_version)
            || !image_ref(&self.image_ref)
            || !image_id(&self.image_id)
            || self.materials.len() != 13
        {
            return Err(Refused);
        }
        let mut roles = BTreeSet::new();
        let mut references = BTreeSet::new();
        for material in &self.materials {
            let role = proto::RuntimeMaterialRole::from_str_name(&material.role).ok_or(Refused)?;
            if !(1..=13).contains(&(role as i32))
                || !roles.insert(role as i32)
                || !references.insert(&material.reference)
                || !reference(&material.reference)
                || !identifier(&material.version)
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
}

// Derived structs also accept positional arrays. Protected enrollment requires
// objects at both levels; duplicate fields were rejected before Value creation.
pub(super) fn optional<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<LaunchEnrollment>, D::Error> {
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if !value.is_object()
        || !value
            .get("materials")
            .and_then(Value::as_array)
            .is_some_and(|materials| materials.iter().all(Value::is_object))
    {
        return Err(serde::de::Error::custom("invalid launch enrollment"));
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|_| serde::de::Error::custom("invalid launch enrollment"))
}

impl Entry {
    /// Join authenticated-agent metadata to protected enrollment and the owner's
    /// freshly compiled configuration. The caller must prove current authority,
    /// publication and original-fence provenance; this function grants neither.
    /// Original fence is positive and preserved, never rewritten on adoption.
    pub(in crate::proxy::managed_authority) fn registration(
        &self,
        attestation: &proto::RuntimeLaunchAttestation,
        configuration: &proto::RuntimeConfiguration,
        host_policy_version: &str,
        deployment_bindings_version: &str,
    ) -> Result<DeploymentRegistration, Refused> {
        let expected = self.launch.as_ref().ok_or(Refused)?;
        expected.validate()?;
        // Bound generated encodings before cloning nested messages or hashing.
        bounded_json(attestation, 32_768)?;
        let configuration_json = bounded_json(configuration, 262_144)?;
        crate::contract_json::decode_management_json::<proto::RuntimeConfiguration>(
            &configuration_json,
        )
        .map_err(|_| Refused)?;
        let launch = attestation.launch.as_ref().ok_or(Refused)?;
        let target = launch.target.as_ref().ok_or(Refused)?;
        let health = launch.health.as_ref().ok_or(Refused)?;
        let spec = crate::proxy::ProxySpec::try_from(configuration.spec.clone().ok_or(Refused)?)
            .map_err(|_| Refused)?;
        crate::proxy::validate_proxy_spec(&spec).map_err(|_| Refused)?;
        let proof_sha256 = digest(&attestation.instance_proof_sha256)?;
        // CP cannot recompute this digest: the immutable files live on the agent.
        digest(&attestation.staged_manifest_sha256)?;
        digest(&launch.launch_context_hash)?;
        digest(&launch.runtime_manifest_hash)?;
        if attestation.schema_version != 1
            || launch.schema_version != 1
            || configuration.schema_version != 1
            || attestation.installation_id != self.installation_id
            || target.workspace_id != self.workspace_id
            || target.namespace_id != self.namespace_id
            || target.proxy_id != self.proxy_id
            || target.revision_id != self.revision_id
            || configuration.workspace_id != target.workspace_id
            || configuration.namespace_id != target.namespace_id
            || configuration.proxy_id != target.proxy_id
            || configuration.revision_id != target.revision_id
            || configuration.generation != target.generation
            || !positive(target.generation)
            || !positive(target.fencing_token)
            || !apex_domain::is_lowercase_uuidv7(&launch.process_instance_id)
            || launch.authority_profile_ref != self.authority_profile_ref
            || launch.authority_profile_version != self.authority_profile_version
            || host_policy_version != expected.host_policy_version
            || deployment_bindings_version != expected.deployment_bindings_version
            || launch.config_hash != expected.config_hash
            || configuration.config_hash != expected.config_hash
            || crate::proxy::store::published_config_hash(&spec) != expected.config_hash
            || launch.runtime_manifest_hash != configuration.runtime_manifest_hash
            || crate::proxy::runtime_manifest_hash(configuration).map_err(|_| Refused)?
                != configuration.runtime_manifest_hash
            || launch.image_ref != expected.image_ref
            || configuration.image_ref != expected.image_ref
            || expected
                .image_ref
                .rsplit_once('@')
                .map(|(_, digest)| digest)
                != Some(spec.runtime_profile.image_digest.as_str())
            || attestation.image_id != expected.image_id
            || launch.launch_context_hash != launch_hash(launch)?
            || health.port != 8081
            || launch.materials.len() != expected.materials.len()
        {
            return Err(Refused);
        }
        // Exact producer order, never sorted by role. Independent image ID above
        // is the OCI config ID, not the image reference's manifest digest.
        for (actual, wanted) in launch.materials.iter().zip(&expected.materials) {
            if proto::RuntimeMaterialRole::try_from(actual.role)
                .ok()
                .map(|r| r.as_str_name())
                != Some(wanted.role.as_str())
                || actual.reference != wanted.reference
                || actual.version != wanted.version
                || configuration.secret_refs.contains(&actual.reference)
                || (actual.role == proto::RuntimeMaterialRole::HealthToken as i32
                    && health.credential_ref != actual.reference)
            {
                return Err(Refused);
            }
        }
        Ok(DeploymentRegistration {
            binding: proto::ManagedDeploymentBinding {
                installation_id: self.installation_id.clone(),
                target: Some(target.clone()),
                process_instance_id: launch.process_instance_id.clone(),
                config_hash: launch.config_hash.clone(),
                launch_context_hash: launch.launch_context_hash.clone(),
            },
            configuration: configuration.clone(),
            authority_profile_ref: self.authority_profile_ref.clone(),
            authority_profile_version: self.authority_profile_version.clone(),
            proof_sha256,
        })
    }
}

fn positive(value: u64) -> bool {
    value > 0 && i64::try_from(value).is_ok()
}

fn reference(value: &str) -> bool {
    value.len() <= 256
        && value.strip_prefix("secret://").is_some_and(|tail| {
            tail.as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && tail
                    .split('/')
                    .all(|part| part != "." && apex_domain::is_scope_identifier(part))
        })
}

fn image_id(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|value| digest(value).is_ok())
}

// Same lexical image shape as the agent producer/compiler; no DNS or approval.
fn image_ref(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let Some((name, digest)) = value.split_once('@') else {
        return false;
    };
    let Some((registry, repository)) = name.split_once('/') else {
        return false;
    };
    let registry_url = format!("https://{registry}/");
    if !image_id(digest)
        || !registry.contains('.')
        || registry_url.len() > 512
        || registry_url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    let Ok(url) = url::Url::parse(&registry_url) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.origin().ascii_serialization() == format!("https://{registry}")
        && repository.split('/').all(|part| {
            !part.is_empty()
                && !part.contains("..")
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        })
}

// Matches the actual agent's launch/hash.rs: bounded generated ProtoJSON,
// recursively byte-sorted object keys, original array order, omit only self hash.
fn launch_hash(launch: &proto::RuntimeLaunchContext) -> Result<String, Refused> {
    let mut value: Value =
        serde_json::from_slice(&bounded_json(launch, 16_384)?).map_err(|_| Refused)?;
    value
        .as_object_mut()
        .ok_or(Refused)?
        .remove("launchContextHash");
    Ok(format!(
        "{:x}",
        Sha256::digest(bounded_json(&sorted(value), 16_384)?)
    ))
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut fields: Vec<_> = fields.into_iter().collect();
            fields.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            Value::Object(fields.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

fn bounded_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, Refused> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::other("launch encoding bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| Refused)?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests;
