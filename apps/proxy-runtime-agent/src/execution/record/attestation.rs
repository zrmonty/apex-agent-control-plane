//! Public digest evidence from an already verified sealed stage; not a grant.
use super::{Installed, Phase, proto};
use sha2::{Digest, Sha256};

impl Installed {
    pub(in crate::execution) fn attestation(
        &self,
        installation: &str,
    ) -> Result<Option<proto::RuntimeLaunchAttestation>, &'static str> {
        const ERROR: &str = "RUNTIME_INSTANCE_ATTESTATION_REFUSED";
        let paired = self.network.is_some()
            || self.guard_stage.is_some()
            || self.gateway_stage.is_some()
            || self.paired_containers.is_some();
        if self.instance_proof_version.is_none() && !paired {
            return Ok(None); // Legacy adoption deliberately remains non-admittable.
        }
        let (files, image_id) = if paired {
            let pair = self.paired_containers.as_ref().ok_or(ERROR)?;
            pair.validate(installation, self).map_err(|_| ERROR)?;
            if pair.phase != crate::execution::paired::Phase::Verified {
                return Err(ERROR);
            }
            // The old single-container slots are not the paired gateway's
            // sealed material or image identity. Never fall back to them.
            let gateway = self.gateway_stage.as_ref().ok_or(ERROR)?;
            (&gateway.files, &pair.gateway_image_id)
        } else {
            if self.phase != Phase::Installed {
                return Err(ERROR);
            }
            (&self.files, &self.image_id)
        };
        let proof_hash = files.get("instance-proof").ok_or(ERROR)?;
        let launch: proto::RuntimeLaunchContext =
            serde_json::from_str(&self.launch_json).map_err(|_| ERROR)?;
        if self.instance_proof_version != Some(1)
            || !crate::shapes::uuid_v7(installation)
            || !crate::shapes::hex_hash(proof_hash)
            || !image_id
                .strip_prefix("sha256:")
                .is_some_and(crate::shapes::hex_hash)
            || launch.schema_version != 1
            || launch.target != self.original.target
            || launch.process_instance_id != self.instance
            || launch.config_hash != self.original.config_hash
            || !crate::shapes::hex_hash(&launch.launch_context_hash)
            || !crate::shapes::hex_hash(&launch.runtime_manifest_hash)
        {
            return Err(ERROR);
        }
        Ok(Some(proto::RuntimeLaunchAttestation {
            schema_version: 1,
            installation_id: installation.into(),
            launch: Some(launch),
            instance_proof_sha256: proof_hash.clone(),
            staged_manifest_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(files).map_err(|_| ERROR)?)
            ),
            image_id: image_id.clone(),
        }))
    }
}
