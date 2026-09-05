//! Owned, scope-bound inputs for durable operations; no browser-supplied secrets.
use crate::proxy::{ProxyId, ProxyRevisionId};
use crate::{ExactScope, proto};
use apex_durability::proto::EventEnvelope;

#[derive(Debug, Clone)]
pub struct SubmitProxyOperation {
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub request_id: String,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub revision_id: ProxyRevisionId,
    pub expected_generation: u64,
    pub desired_state: proto::ProxyDesiredState,
    /// A server-built validated envelope, frozen atomically with acceptance.
    pub evidence: EventEnvelope,
}

#[derive(Debug, Clone)]
pub struct LeasedProxyOperation {
    pub operation: proto::ProxyOperation,
    pub worker_id: String,
    pub fencing_token: u64,
    pub lease_expires_at_micros: u64,
}
