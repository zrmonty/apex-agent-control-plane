//! Atomic management input. Runtime effects belong to the durable controller.
use crate::proxy::{ProxyId, ProxyRevisionId, SecretRef};
use crate::{ExactScope, proto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedLifecycleAction {
    Deploy,
    Resume,
    Pause,
    Retire,
    Rotate { secret_refs: Vec<SecretRef> },
    Rollback { target_revision_id: ProxyRevisionId },
}

#[derive(Debug, Clone)]
pub struct ManagedLifecycleInput {
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub request_id: String,
    pub revision_id: ProxyRevisionId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
    pub action: ManagedLifecycleAction,
    /// Result of the service's existing scoped approval authority.
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AcceptedManagedLifecycle {
    pub proxy: proto::McpProxy,
    pub revision: proto::McpProxyRevision,
    pub operation: proto::ProxyOperation,
}
