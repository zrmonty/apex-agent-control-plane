//! Bounded deployment metadata, never publication proof or an execution permit.

use std::{collections::BTreeSet, fmt};

use super::RuntimeAuthorityError;
use crate::{
    ExactScope, contract_json, proto,
    proxy::{McpProxyRevision, RuntimeDeploymentBindings, SecretRef, compile_runtime_config},
};

pub(super) struct DeploymentCatalog {
    version: String,
    valid_from_unix_us: u64,
    expires_at_unix_us: u64,
    profiles: Vec<Profile>,
}

struct Profile {
    installation_id: String,
    proxy_id: String,
    revision_id: String,
    host_policy_version: String,
    bindings: RuntimeDeploymentBindings,
}

impl DeploymentCatalog {
    pub(super) fn parse_json(input: &[u8]) -> Result<Self, RuntimeAuthorityError> {
        require(!input.is_empty() && input.len() <= 262_144)?;
        // Decode the original bytes: duplicate decoded keys, unknown fields,
        // aliases and noncanonical uint64 spellings must reach the shared guard.
        let document: proto::RuntimeDeploymentBindingsDocument =
            contract_json::decode_management_json(input)
                .map_err(|_| RuntimeAuthorityError::Unavailable)?;
        require(
            document.schema_version == 1
                && identifier(&document.version)
                && positive_i64(document.valid_from_unix_us)
                && positive_i64(document.expires_at_unix_us)
                && document.valid_from_unix_us < document.expires_at_unix_us
                && (1..=32).contains(&document.profiles.len()),
        )?;
        let mut selectors = BTreeSet::new();
        for profile in &document.profiles {
            // Host-policy version is a required match, not an alternative
            // selector that could authorize two profiles for the same target.
            require(selectors.insert((
                &profile.installation_id,
                &profile.workspace_id,
                &profile.namespace_id,
                &profile.proxy_id,
                &profile.revision_id,
            )))?;
        }
        let profiles = document
            .profiles
            .into_iter()
            .map(Profile::parse)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            version: document.version,
            valid_from_unix_us: document.valid_from_unix_us,
            expires_at_unix_us: document.expires_at_unix_us,
            profiles,
        })
    }

    pub(super) fn version(&self) -> &str {
        &self.version
    }

    pub(super) fn check_current(&self, now: u64) -> Result<(), RuntimeAuthorityError> {
        require(now >= self.valid_from_unix_us && now < self.expires_at_unix_us)
    }

    pub(super) fn compile(
        &self,
        target: &proto::RuntimeTarget,
        installation_id: &str,
        host_policy_version: &str,
        revision: &McpProxyRevision,
    ) -> Result<proto::RuntimeConfiguration, RuntimeAuthorityError> {
        let denied = RuntimeAuthorityError::EnrollmentDenied;
        if !positive_i64(target.generation)
            || !positive_i64(target.fencing_token)
            || target.proxy_id != revision.proxy_id.to_string()
            || target.revision_id != revision.revision_id.to_string()
        {
            return Err(denied);
        }
        // Exact comparisons against parsed identifiers also reject malformed
        // caller IDs. Revision carries no scope: the parent owns the PG scoped
        // publication lookup, and this profile must match that original target.
        let profile = self
            .profiles
            .iter()
            .find(|profile| {
                profile.installation_id == installation_id
                    && profile.bindings.scope.workspace_id == target.workspace_id
                    && profile.bindings.scope.namespace_id == target.namespace_id
                    && profile.proxy_id == target.proxy_id
                    && profile.revision_id == target.revision_id
                    && profile.host_policy_version == host_policy_version
            })
            .ok_or(denied)?;
        let mut bindings = profile.bindings.clone();
        // Only the parent's PG-verified current operation supplies generation.
        // The owner checks freshness/rotation around this pure compilation.
        bindings.generation = target.generation;
        compile_runtime_config(revision, &bindings).map_err(|_| RuntimeAuthorityError::Unavailable)
    }
}

impl Profile {
    fn parse(profile: proto::RuntimeDeploymentProfile) -> Result<Self, RuntimeAuthorityError> {
        require(
            [
                &profile.installation_id,
                &profile.proxy_id,
                &profile.revision_id,
            ]
            .into_iter()
            .all(|id| apex_domain::is_lowercase_uuidv7(id))
                && apex_domain::is_scope_identifier(&profile.workspace_id)
                && apex_domain::is_scope_identifier(&profile.namespace_id)
                && identifier(&profile.host_policy_version)
                && (1..=256).contains(&profile.images.len())
                && profile.secret_refs.len() <= 4096
                && profile.tool_schemas.len() <= 256
                && profile.approved_output_profiles.len() <= 256
                && (1..=64).contains(&profile.network_grants.len()),
        )?;
        let mut digests = BTreeSet::new();
        for image in &profile.images {
            require(
                digests.insert(&image.digest)
                    && image.digest.strip_prefix("sha256:").is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
                    })
                    && !image.image_ref.is_empty()
                    && image.image_ref.len() <= 512,
            )?;
        }
        unique(profile.secret_refs.iter())?;
        let secret_refs = profile
            .secret_refs
            .into_iter()
            .map(|reference| {
                SecretRef::from_reference(reference).map_err(|_| RuntimeAuthorityError::Unavailable)
            })
            .collect::<Result<_, _>>()?;
        unique(profile.approved_output_profiles.iter())?;
        require(
            profile
                .approved_output_profiles
                .iter()
                .all(|id| identifier(id)),
        )?;
        unique(
            profile
                .tool_schemas
                .iter()
                .map(|schema| (&schema.upstream_id, &schema.tool_name)),
        )?;
        unique(profile.network_grants.iter().map(|grant| &grant.grant_id))?;
        unique(
            profile
                .network_grants
                .iter()
                .map(|grant| (&grant.host, grant.port)),
        )?;
        for grant in &profile.network_grants {
            require(identifier(&grant.grant_id) && grant.approved_cidrs.len() <= 64)?;
            unique(grant.approved_cidrs.iter())?;
        }
        let auth = profile.auth.ok_or(RuntimeAuthorityError::Unavailable)?;
        require(
            (1..=64).contains(&auth.required_scopes.len())
                && auth.required_scopes.iter().all(|scope| identifier(scope)),
        )?;
        unique(auth.required_scopes.iter())?;
        let telemetry = profile
            .telemetry
            .ok_or(RuntimeAuthorityError::Unavailable)?;
        // Revision-independent execution/telemetry bounds must reject the whole
        // catalog during startup/refresh, not only a later selected compilation.
        crate::proxy::runtime_config::validate_deployment_limits(profile.pid_limit, &telemetry)
            .map_err(|_| RuntimeAuthorityError::Unavailable)?;
        Ok(Self {
            installation_id: profile.installation_id,
            proxy_id: profile.proxy_id,
            revision_id: profile.revision_id,
            host_policy_version: profile.host_policy_version,
            bindings: RuntimeDeploymentBindings {
                scope: ExactScope {
                    workspace_id: profile.workspace_id,
                    namespace_id: profile.namespace_id,
                },
                // Not a deployable binding until compile injects the verified value.
                generation: 0,
                resource_url: profile.resource_url,
                image_catalog: profile
                    .images
                    .into_iter()
                    .map(|image| (image.digest, image.image_ref))
                    .collect(),
                secret_refs,
                tool_schemas: profile.tool_schemas,
                approved_output_profiles: profile.approved_output_profiles.into_iter().collect(),
                network_grants: profile.network_grants,
                auth,
                telemetry,
                pid_limit: profile.pid_limit,
            },
        })
    }
}

fn positive_i64(value: u64) -> bool {
    value != 0 && i64::try_from(value).is_ok()
}

fn identifier(value: &str) -> bool {
    value.len() <= 128 && apex_domain::is_scope_identifier(value)
}

fn unique<T: Ord>(items: impl IntoIterator<Item = T>) -> Result<(), RuntimeAuthorityError> {
    let mut seen = BTreeSet::new();
    require(items.into_iter().all(|item| seen.insert(item)))
}

fn require(condition: bool) -> Result<(), RuntimeAuthorityError> {
    if condition {
        Ok(())
    } else {
        Err(RuntimeAuthorityError::Unavailable)
    }
}

impl fmt::Debug for DeploymentCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeploymentCatalog { [redacted] }")
    }
}

#[cfg(test)]
mod tests;
