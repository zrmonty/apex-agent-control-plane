//! Production owner: construct/start/join outside Tokio and retain on every error.
use super::{Refused, service};
use crate::{GovernanceConfig, ProxyError, proto};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub struct ManagedAuthorityOwner {
    inner: service::Owner,
    settings: Option<Settings>,
}
struct Settings {
    path: PathBuf,
    base: PathBuf,
    database: Zeroizing<String>,
    policy: GovernanceConfig,
}
impl ManagedAuthorityOwner {
    pub fn new(
        path: PathBuf,
        base: PathBuf,
        database: &str,
        policy: GovernanceConfig,
    ) -> Result<Self, ProxyError> {
        if !path.is_absolute()
            || !base.is_absolute()
            || !path.starts_with(&base)
            || path == base
            || database.trim().is_empty()
        {
            return Err(unavailable(Refused));
        }
        Ok(Self {
            inner: service::Owner::new().map_err(unavailable)?,
            settings: Some(Settings {
                path,
                base,
                database: Zeroizing::new(database.to_owned()),
                policy,
            }),
        })
    }
    pub fn start(&mut self) -> Result<service::Service, ProxyError> {
        let settings = self.settings.take().ok_or_else(|| unavailable(Refused))?;
        self.inner
            .start(
                settings.path,
                settings.base,
                &settings.database,
                settings.policy,
            )
            .map_err(unavailable)
    }
    /// Bind the already validated deployment-owned Controller transport before
    /// start. No workload request supplies endpoints, credentials or host roles.
    pub fn configure_network_inspection(
        &mut self,
        execution: &crate::RuntimeExecutionOwner,
    ) -> Result<(), ProxyError> {
        if self.settings.is_none() {
            return Err(unavailable(Refused));
        }
        self.inner
            .configure_network(execution.configuration().clone())
            .map_err(unavailable)
    }
    pub fn request_shutdown(&self) {
        self.inner.request_shutdown();
    }
    pub fn shutdown(&mut self) -> Result<(), ProxyError> {
        self.inner.shutdown().map_err(unavailable)
    }
}

pub fn bounded_managed_runtime_authority_server(
    service: service::Service,
) -> proto::managed_runtime_authority_server::ManagedRuntimeAuthorityServer<service::Service> {
    proto::managed_runtime_authority_server::ManagedRuntimeAuthorityServer::new(service)
        .max_decoding_message_size(16_384)
        .max_encoding_message_size(16_384)
}
pub fn bounded_managed_proxy_governance_server(
    service: service::Service,
) -> proto::managed_proxy_governance_server::ManagedProxyGovernanceServer<service::Service> {
    proto::managed_proxy_governance_server::ManagedProxyGovernanceServer::new(service)
        .max_decoding_message_size(16_384)
        .max_encoding_message_size(16_384)
}
pub fn bounded_managed_network_readiness_server(
    service: service::Service,
) -> proto::managed_network_readiness_server::ManagedNetworkReadinessServer<service::Service> {
    proto::managed_network_readiness_server::ManagedNetworkReadinessServer::new(service)
        .max_decoding_message_size(4096)
        .max_encoding_message_size(4096)
}
fn unavailable(_: Refused) -> ProxyError {
    ProxyError::new(
        "MANAGED_AUTHORITY_UNAVAILABLE",
        "Managed authority unavailable.",
    )
}
