//! Managed workload credentials are independent of operator and agent roles.
//! Production service composition is kept closed until every owner is wired.
#![allow(dead_code)] // Private staged implementation; not yet registered at root.

mod call;
mod pool;
mod presentation;
mod profile;
mod protected;
mod refresh;
mod root;
pub use root::{
    ManagedAuthorityOwner, bounded_managed_network_readiness_server,
    bounded_managed_proxy_governance_server, bounded_managed_runtime_authority_server,
};
pub use service::Service as ManagedAuthorityService;
mod service;
mod state;

/// Current authenticated observation data, never a grant or caller-made TLS view.
pub(crate) struct RegistrationInput {
    pub lease: crate::LeasedProxyOperation,
    pub authority: crate::proto::RuntimeAuthoritySnapshot,
    pub configuration: crate::proto::RuntimeConfiguration,
    pub deployment_bindings_version: String,
    pub attestation: crate::proto::RuntimeLaunchAttestation,
    pub recheck_authority: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    pub started: std::time::Instant,
    pub budget: std::time::Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Refused;
