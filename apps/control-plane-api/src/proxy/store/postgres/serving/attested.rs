//! Metadata persistence only; the service authenticates the original agent RPC.
use super::*;
use sha2::{Digest, Sha256};

impl PostgresProxyStore {
    pub(crate) fn register_attested_deployment_checked(
        &self,
        lease: &LeasedProxyOperation,
        input: &DeploymentRegistration,
        attestation: &proto::RuntimeLaunchAttestation,
        authority: &proto::RuntimeAuthoritySnapshot,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<String, ProxyError> {
        check()?;
        let binding = &input.binding;
        let launch = attestation.launch.as_ref().ok_or_else(refused)?;
        let current = authority.target.as_ref().ok_or_else(refused)?;
        let original = binding.target.as_ref().ok_or_else(refused)?;
        let bytes = attestation.encode_to_vec();
        let observed = authority.encode_to_vec();
        if bytes.len() > 16384
            || observed.len() > 4096
            || attestation.schema_version != 1
            || authority.schema_version != 1
            || attestation.installation_id != binding.installation_id
            || authority.installation_id != binding.installation_id
            || launch.target != binding.target
            || launch.process_instance_id != binding.process_instance_id
            || launch.config_hash != binding.config_hash
            || launch.launch_context_hash != binding.launch_context_hash
            || attestation.instance_proof_sha256
                != input
                    .proof_sha256
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            || !transaction::digest(&attestation.staged_manifest_sha256)
            || !attestation
                .image_id
                .strip_prefix("sha256:")
                .is_some_and(transaction::digest)
            || authority.operation_id != lease.operation.operation_id
            || authority.config_hash != binding.config_hash
            || current.workspace_id != original.workspace_id
            || current.namespace_id != original.namespace_id
            || current.proxy_id != original.proxy_id
            || current.revision_id != original.revision_id
            || current.generation != original.generation
            || current.fencing_token != lease.fencing_token
        {
            return Err(refused());
        }
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            let existing = tx.query("SELECT 1 FROM mcp_proxy_deployments WHERE instance_id=$1", &[&key.instance])?;
            let provenance = tx.query("SELECT attestation_bytes FROM mcp_proxy_deployment_attestations WHERE instance_id=$1", &[&key.instance])?;
            if !existing.is_empty() && provenance.is_empty() {
                return Err(refused()); // No retroactive provenance for an unproven identity.
            }
            registration::register(tx, key, lease, input)?;
            if let Some(row) = provenance.first() {
                if row.get::<_, Vec<u8>>(0) != bytes {
                    return Err(refused());
                }
            } else {
                tx.execute("INSERT INTO mcp_proxy_deployment_attestations(instance_id,attestation_bytes,authority_bytes) VALUES($1,$2,$3)", &[&key.instance,&bytes,&observed])?;
            }
            Ok(format!("{:x}", Sha256::digest(&bytes)))
        })
    }
}
