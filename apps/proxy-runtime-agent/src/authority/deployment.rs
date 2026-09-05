//! Private construction from an online response, not an execution permit.
use super::AuthorityClientError;
use crate::proto;
use prost::Message;

pub(super) const MESSAGE_LIMIT: usize = 270_336;

/// Validated point-in-time deployment data. Must be rechecked before effects.
pub struct ResolvedDeployment {
    authority: proto::RuntimeAuthoritySnapshot,
    configuration: proto::RuntimeConfiguration,
    version: String,
}

impl ResolvedDeployment {
    /// Published configuration obtained through the pinned online authority.
    pub fn configuration(&self) -> &proto::RuntimeConfiguration {
        &self.configuration
    }
    /// Current-operation observation at resolution time, not a lease grant.
    pub fn authority(&self) -> &proto::RuntimeAuthoritySnapshot {
        &self.authority
    }
    /// Deployment metadata version used by the authority compiler.
    pub fn bindings_version(&self) -> &str {
        &self.version
    }

    pub(super) fn parse(
        reply: proto::RuntimeDeploymentSnapshot,
    ) -> Result<Self, AuthorityClientError> {
        let invalid = AuthorityClientError::InvalidSnapshot;
        if reply.schema_version != 1
            || reply.encoded_len() > MESSAGE_LIMIT
            || reply.deployment_bindings_version.len() > 128
            || !apex_domain::is_scope_identifier(&reply.deployment_bindings_version)
        {
            return Err(invalid);
        }
        let authority = reply.authority.ok_or(invalid)?;
        let configuration = reply.configuration.ok_or(invalid)?;
        let target = authority.target.as_ref().ok_or(invalid)?;
        crate::check_target_configuration_binding(target, &configuration).map_err(|_| invalid)?;
        if configuration.config_hash != authority.config_hash
            || crate::runtime_manifest_hash(&configuration).map_err(|_| invalid)?
                != configuration.runtime_manifest_hash
        {
            return Err(invalid);
        }
        // Same serialized configuration ceiling as the authority compiler/stager.
        let json = serde_json::to_vec(&configuration).map_err(|_| invalid)?;
        if json.len() > 262_144 {
            return Err(invalid);
        }
        Ok(Self {
            authority,
            configuration,
            version: reply.deployment_bindings_version,
        })
    }
}

impl std::fmt::Debug for ResolvedDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResolvedDeployment { [redacted] }")
    }
}

#[cfg(test)]
mod tests;
