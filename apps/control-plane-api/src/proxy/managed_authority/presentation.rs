//! Only digests survive parsing; original secret metadata remains transport-owned.
use super::{
    Refused,
    profile::{Entry, Profile},
};
use crate::proxy::store::DeploymentRegistration;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tonic::metadata::MetadataMap;

pub(super) struct Presentation {
    certificate: [u8; 32],
    token: [u8; 32],
    proof: [u8; 32],
}

impl Presentation {
    pub(super) fn from_request<T>(request: &tonic::Request<T>) -> Result<Self, Refused> {
        // The shared extractor reads the actual tonic TLS acceptor extension;
        // unlike the agent test helper it accepts no injected PeerIdentity.
        let peer = apex_auth::PeerIdentity::from_request(request).ok_or(Refused)?;
        Self::parse(request.metadata(), peer.certificate_sha256)
    }
    fn parse(metadata: &MetadataMap, certificate: [u8; 32]) -> Result<Self, Refused> {
        if metadata.get_all("authorization").iter().count() != 1
            || metadata
                .get_all_bin("apex-instance-proof-bin")
                .iter()
                .count()
                != 1
        {
            return Err(Refused);
        }
        let token = metadata
            .get("authorization")
            .ok_or(Refused)?
            .to_str()
            .map_err(|_| Refused)?
            .strip_prefix("Bearer ")
            .ok_or(Refused)?;
        let payload = token.trim_end_matches('=');
        if !(16..=4096).contains(&payload.len())
            || token.len() - payload.len() > 2
            || !payload.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'-')
            })
        {
            return Err(Refused);
        }
        let encoded = metadata.get_bin("apex-instance-proof-bin").ok_or(Refused)?;
        // Bound before base64 allocation. 32 bytes require43 unpadded or44 padded.
        if !(43..=44).contains(&encoded.as_encoded_bytes().len()) {
            return Err(Refused);
        }
        let proof = encoded.to_bytes().map_err(|_| Refused)?;
        if proof.len() != 32 {
            return Err(Refused);
        }
        Ok(Self {
            certificate,
            token: Sha256::digest(token.as_bytes()).into(),
            proof: Sha256::digest(&proof).into(),
        })
    }
    pub(super) fn verify<'a>(
        &self,
        profile: &'a Profile,
        registration: &DeploymentRegistration,
        now: u64,
    ) -> Result<&'a Entry, Refused> {
        if !bool::from(self.proof.ct_eq(&registration.proof_sha256)) {
            return Err(Refused);
        }
        let selected = self.select(profile, &registration.binding, now)?;
        if selected.authority_profile_ref != registration.authority_profile_ref
            || selected.authority_profile_version != registration.authority_profile_version
        {
            return Err(Refused);
        }
        Ok(selected)
    }

    /// Cheap profile intersection precedes database admission. It is deliberately
    /// not a grant: instance proof still requires the exact registered digest.
    pub(super) fn select<'a>(
        &self,
        profile: &'a Profile,
        binding: &crate::proto::ManagedDeploymentBinding,
        now: u64,
    ) -> Result<&'a Entry, Refused> {
        if now < profile.valid_from || now >= profile.expires {
            return Err(Refused);
        }
        let target = binding.target.as_ref().ok_or(Refused)?;
        profile
            .entries
            .iter()
            .find(|entry| {
                entry.installation_id == binding.installation_id
                    && entry.workspace_id == target.workspace_id
                    && entry.namespace_id == target.namespace_id
                    && entry.proxy_id == target.proxy_id
                    && entry.revision_id == target.revision_id
                    && entry
                        .credentials
                        .iter()
                        .any(|key| key.matches(&self.certificate, &self.token))
            })
            .ok_or(Refused)
    }
}

#[cfg(test)]
mod tests;
