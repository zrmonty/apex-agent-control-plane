//! Pure deployment-to-launch binding. Prepared data never permits execution.

use crate::{authority::ResolvedDeployment, proto, secrets::ScopedMaterial};
use std::fmt;

mod catalog;
mod hash;
mod validation;

/// Strict deployment-owned metadata, never supplied by a runtime RPC caller.
pub struct LaunchCatalog {
    document: catalog::Document,
}

/// Static refusals without input values or source errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    InvalidCatalog,
    BindingMismatch,
    InvalidInstance,
    OutsideValidity,
    InvalidConfiguration,
    Encoding,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCatalog => "launch catalog invalid",
            Self::BindingMismatch => "launch binding mismatch",
            Self::InvalidInstance => "launch instance invalid",
            Self::OutsideValidity => "launch catalog outside validity",
            Self::InvalidConfiguration => "launch configuration invalid",
            Self::Encoding => "launch encoding refused",
        })
    }
}
impl std::error::Error for LaunchError {}

/// Immutable prepared bytes and material metadata; not an execution permit.
pub struct PreparedLaunch {
    context: proto::RuntimeLaunchContext,
    configuration_json: Vec<u8>,
    launch_json: Vec<u8>,
    materials: Vec<ScopedMaterial>,
    image_catalog_id: String,
    catalog_version: String,
}

impl PreparedLaunch {
    /// Generated launch metadata, with its canonical integrity digest.
    pub fn context(&self) -> &proto::RuntimeLaunchContext {
        &self.context
    }
    /// Generated configuration ProtoJSON, at most 262144 bytes.
    pub fn configuration_json(&self) -> &[u8] {
        &self.configuration_json
    }
    /// Generated launch ProtoJSON, at most 16384 bytes.
    pub fn launch_json(&self) -> &[u8] {
        &self.launch_json
    }
    /// Exact deployment-scoped material selection; contains no secret bytes.
    pub fn materials(&self) -> &[ScopedMaterial] {
        &self.materials
    }
    /// ID for later independent image-catalog selection/signature verification.
    pub fn image_catalog_id(&self) -> &str {
        &self.image_catalog_id
    }
    /// Version of the deployment-owned launch catalog used for preparation.
    pub fn catalog_version(&self) -> &str {
        &self.catalog_version
    }
}

impl LaunchCatalog {
    #[cfg(test)]
    pub(crate) fn fixture_prepare_data(
        &self,
        authority: &proto::RuntimeAuthoritySnapshot,
        configuration: &proto::RuntimeConfiguration,
        bindings: &str,
        instance: &str,
    ) -> Result<PreparedLaunch, LaunchError> {
        self.prepare_data(authority, configuration, bindings, instance)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn recover(
        &self,
        resolved: &ResolvedDeployment,
        original: &proto::RuntimeTarget,
        instance: &str,
    ) -> Result<PreparedLaunch, LaunchError> {
        let mut authority = resolved.authority().clone();
        let current = authority
            .target
            .as_ref()
            .ok_or(LaunchError::BindingMismatch)?;
        let mut comparison = original.clone();
        comparison.fencing_token = current.fencing_token;
        if comparison != *current || original.fencing_token > current.fencing_token {
            return Err(LaunchError::BindingMismatch);
        }
        // Pure immutable launch reconstruction; never used as online authority.
        authority.target = Some(original.clone());
        self.prepare_data(
            &authority,
            resolved.configuration(),
            resolved.bindings_version(),
            instance,
        )
    }
    /// Parse bounded deployment-owned bytes, checking every profile eagerly.
    /// This does not authenticate the document's provenance or currentness.
    ///
    /// # Errors
    /// Refuses malformed, oversized, ambiguous or unsupported catalog data.
    pub fn parse(bytes: &[u8]) -> Result<Self, LaunchError> {
        catalog::parse(bytes).map(|document| Self { document })
    }

    /// Bind metadata to an online resolved deployment at its authority timestamp.
    /// This is pure preparation: no clock, file, secret, signature or engine IO.
    /// The future owner must protect/refresh the catalog and recheck authority,
    /// policy and expiry before effects; this point-in-time result is no permit.
    ///
    /// # Errors
    /// Refuses mismatched bindings, invalid instance IDs, out-of-interval
    /// authority timestamps, secret overlap, or invalid/oversized encoding.
    pub fn prepare(
        &self,
        resolved: &ResolvedDeployment,
        instance: &str,
    ) -> Result<PreparedLaunch, LaunchError> {
        self.prepare_data(
            resolved.authority(),
            resolved.configuration(),
            resolved.bindings_version(),
            instance,
        )
    }

    // Private deterministic seam: generated data alone is never public authority.
    fn prepare_data(
        &self,
        authority: &proto::RuntimeAuthoritySnapshot,
        configuration: &proto::RuntimeConfiguration,
        bindings_version: &str,
        instance: &str,
    ) -> Result<PreparedLaunch, LaunchError> {
        if !crate::shapes::uuid_v7(instance) {
            return Err(LaunchError::InvalidInstance);
        }
        let target = authority
            .target
            .as_ref()
            .ok_or(LaunchError::BindingMismatch)?;
        validation::configuration(authority, configuration)?;
        let checked = authority.checked_at_unix_us;
        if !validation::sql_positive(checked)
            || checked < self.document.valid_from_unix_us
            || checked >= self.document.expires_at_unix_us
        {
            return Err(LaunchError::OutsideValidity);
        }
        let profile = self
            .document
            .profiles
            .iter()
            .map(|p| &p.0)
            .find(|p| {
                p.installation_id == authority.installation_id
                    && p.workspace_id == target.workspace_id
                    && p.namespace_id == target.namespace_id
                    && p.proxy_id == target.proxy_id
                    && p.revision_id == target.revision_id
                    && p.host_policy_version == authority.host_policy_version
                    && p.deployment_bindings_version == bindings_version
                    && p.config_hash == authority.config_hash
            })
            .ok_or(LaunchError::BindingMismatch)?;
        if profile
            .materials
            .iter()
            .any(|m| configuration.secret_refs.contains(&m.0.reference))
        {
            return Err(LaunchError::BindingMismatch);
        }
        let configuration_json = hash::bounded_json(configuration, 262_144)
            .map_err(|_| LaunchError::InvalidConfiguration)?;
        let materials: Vec<_> = profile
            .materials
            .iter()
            .map(|m| {
                let m = &m.0;
                ScopedMaterial {
                    workspace_id: profile.workspace_id.clone(),
                    namespace_id: profile.namespace_id.clone(),
                    proxy_id: profile.proxy_id.clone(),
                    reference: m.reference.clone(),
                    version: m.version.clone(),
                    role: m.role.0,
                    source_name: m.source_name.clone(),
                }
            })
            .collect();
        let health = materials
            .iter()
            .find(|m| m.role == proto::RuntimeMaterialRole::HealthToken)
            .ok_or(LaunchError::InvalidCatalog)?;
        let mut context = proto::RuntimeLaunchContext {
            schema_version: 1,
            target: Some(target.clone()),
            config_hash: configuration.config_hash.clone(),
            runtime_manifest_hash: configuration.runtime_manifest_hash.clone(),
            image_ref: configuration.image_ref.clone(),
            process_instance_id: instance.into(),
            health: Some(proto::RuntimeHealthBinding {
                port: 8081,
                credential_ref: health.reference.clone(),
            }),
            materials: materials
                .iter()
                .map(|m| proto::RuntimeMaterialBinding {
                    role: m.role.into(),
                    reference: m.reference.clone(),
                    version: m.version.clone(),
                })
                .collect(),
            launch_context_hash: String::new(),
            authority_profile_ref: profile.authority_profile_ref.clone(),
            authority_profile_version: profile.authority_profile_version.clone(),
        };
        context.launch_context_hash = hash::launch_hash(&context)?;
        let launch_json = hash::bounded_json(&context, 16_384)?;
        Ok(PreparedLaunch {
            context,
            configuration_json,
            launch_json,
            materials,
            image_catalog_id: profile.image_catalog_id.clone(),
            catalog_version: self.document.version.clone(),
        })
    }
}

impl fmt::Debug for LaunchCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LaunchCatalog { [redacted] }")
    }
}
impl fmt::Debug for PreparedLaunch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedLaunch { [redacted; data only] }")
    }
}

#[cfg(test)]
mod tests;
