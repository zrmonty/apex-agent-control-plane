//! Fixed files, zeroizing original buffers, and immutable transport fingerprint.
use super::{AgentConfig, Directory};
use crate::{authority::AuthorityClientConfig, owner::Metadata};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use zeroize::Zeroizing;
#[cfg(test)]
mod network_tests;

pub(crate) struct Deployment {
    pub config: AgentConfig,
    pems: Vec<Zeroizing<Vec<u8>>>,
    pub fingerprint: [u8; 32],
    pub resources: Option<crate::execution::Resources>,
}
impl Deployment {
    pub(crate) fn load(
        directory: &Directory,
        expected: Option<[u8; 32]>,
    ) -> Result<(Self, Metadata), &'static str> {
        let policy = directory.read("peer-policy.json", 65_536)?;
        let catalog = directory.read("launch-catalog.json", 262_144)?;
        let metadata = Metadata::parse(&policy, &catalog)?;
        let mut deployment = Self::transport(directory, expected).map_err(|code| {
            if expected.is_some() {
                "RUNTIME_RESTART_REQUIRED"
            } else {
                code
            }
        })?;
        let metadata = if deployment.config.execution.is_some() {
            metadata.with_execution(
                &directory.read("image-catalog.json", 65_536)?,
                &directory.read("authority-profiles.json", 262_144)?,
                &directory.read("tool-bindings.json", 262_144)?,
            )?
        } else {
            metadata
        };
        let metadata = if deployment
            .config
            .execution
            .as_ref()
            .is_some_and(|c| c.network_profile.is_some())
        {
            metadata.with_network(
                &directory.read("network-catalog.json", 262_144)?,
                &deployment.config.installation_id,
                &deployment.config.host_policy_version,
            )?
        } else {
            metadata
        };
        if expected.is_none() {
            deployment.resources = deployment
                .config
                .execution
                .as_ref()
                .map(|c| crate::execution::Resources::open(c, &deployment.config.installation_id))
                .transpose()?;
        }
        Ok((deployment, metadata))
    }
    fn transport(directory: &Directory, expected: Option<[u8; 32]>) -> Result<Self, &'static str> {
        let bytes = directory.read("agent.json", 65_536)?;
        let mut hash = Sha256::new();
        hash.update(Sha256::digest(&bytes));
        let mut pems = Vec::with_capacity(6);
        for name in [
            "server-ca.pem",
            "server-cert.pem",
            "server-key.pem",
            "authority-ca.pem",
            "authority-client-cert.pem",
            "authority-client-key.pem",
        ] {
            let bytes = directory.read(name, 65_536)?;
            hash.update(Sha256::digest(&bytes));
            pems.push(bytes);
        }
        let fingerprint = hash.finalize().into();
        if expected.is_some_and(|value| value != fingerprint) {
            return Err("RUNTIME_RESTART_REQUIRED");
        }
        let config = AgentConfig::parse(&bytes)?;
        Ok(Self {
            config,
            pems,
            fingerprint,
            resources: None,
        })
    }
    pub(crate) fn server_tls(&self) -> ServerTlsConfig {
        // tonic/rustls own their internal credential copies; all original owned
        // file buffers remain Zeroizing, including failed connect/startup paths.
        ServerTlsConfig::new()
            .client_ca_root(Certificate::from_pem(&*self.pems[0]))
            .identity(Identity::from_pem(&*self.pems[1], &*self.pems[2]))
            .client_auth_optional(false)
            .timeout(std::time::Duration::from_secs(5))
    }
    pub(crate) fn authority_config(&self) -> AuthorityClientConfig {
        AuthorityClientConfig {
            endpoint: self.config.authority_endpoint.clone(),
            tls_server_name: self.config.authority_tls_server_name.clone(),
            ca_pem: self.pems[3].to_vec(),
            client_certificate_pem: self.pems[4].to_vec(),
            client_key_pem: self.pems[5].to_vec(),
            installation_id: self.config.installation_id.clone(),
            agent_identity_id: self.config.agent_identity_id.clone(),
            enrollment_version: self.config.enrollment_version.clone(),
            host_policy_version: self.config.host_policy_version.clone(),
        }
    }
}
