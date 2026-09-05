use super::{
    LifecycleCommand, McpProxyRevision, ProxyError, ProxyId, ProxyLifecycleState,
    ProxyRedactionStatus, ProxyRevisionId, ProxySpec,
};
use crate::ExactScope;

mod canonical;
mod memory;
#[cfg(feature = "postgres")]
mod operations;
mod publish_capabilities;
mod shared;
mod transitions;
#[cfg(feature = "postgres")]
pub use operations::{LeasedProxyOperation, SubmitProxyOperation};

#[cfg(feature = "postgres")]
mod postgres;

pub use memory::InMemoryProxyStore;
#[cfg(feature = "postgres")]
pub use postgres::{PostgresProxyStore, RuntimeOperationSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxy {
    pub proxy_id: ProxyId,
    pub scope: ExactScope,
    pub display_name: String,
    pub slug: String,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub lifecycle_state: ProxyLifecycleState,
    pub redaction_status: ProxyRedactionStatus,
    pub active_revision_id: Option<ProxyRevisionId>,
    pub draft_revision_id: Option<ProxyRevisionId>,
    pub spec: Option<ProxySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProxySummary {
    pub proxy_id: ProxyId,
    pub scope: ExactScope,
    pub display_name: String,
    pub slug: String,
    pub lifecycle_state: ProxyLifecycleState,
    pub redaction_status: ProxyRedactionStatus,
    pub active_revision_id: Option<ProxyRevisionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProxy {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub display_name: String,
    pub slug: String,
    pub description: Option<String>,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProxyResult {
    pub proxy: McpProxy,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateProxyDraft {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
    pub spec: ProxySpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRevision {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub draft_revision_id: ProxyRevisionId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireProxy {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub expected_revision_id: Option<ProxyRevisionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionProxyLifecycle {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
    pub command: LifecycleCommand,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateProxyCredentials {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
    pub secret_refs: Vec<super::SecretRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackProxy {
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub target_revision_id: ProxyRevisionId,
    pub expected_revision_id: Option<ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListProxyActivity {
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub page_size: usize,
    pub page_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyActivity {
    pub activity_id: String,
    pub request_id: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: Option<ProxyRevisionId>,
    pub occurred_at: String,
    pub actor_id: Option<String>,
    pub operation: String,
    pub prior_state: Option<ProxyLifecycleState>,
    pub next_state: ProxyLifecycleState,
    pub reason_code: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListProxyActivityPage {
    pub activity: Vec<ProxyActivity>,
    pub next_page_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListProxies {
    pub scope: ExactScope,
    pub page_size: usize,
    pub page_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListProxiesPage {
    pub proxies: Vec<McpProxySummary>,
    pub next_page_token: String,
}

pub trait ProxyStore: Send + Sync {
    fn create(&self, input: CreateProxy) -> Result<McpProxy, ProxyError> {
        self.create_with_outcome(input).map(|result| result.proxy)
    }
    fn create_with_outcome(&self, input: CreateProxy) -> Result<CreateProxyResult, ProxyError>;
    fn update_draft(&self, input: UpdateProxyDraft) -> Result<McpProxy, ProxyError>;
    fn publish_revision(&self, input: PublishRevision) -> Result<McpProxyRevision, ProxyError>;
    fn get(&self, scope: ExactScope, proxy_id: ProxyId) -> Result<McpProxy, ProxyError>;
    fn list(&self, query: ListProxies) -> Result<ListProxiesPage, ProxyError>;
}

pub trait ProxyRevisionStore: Send + Sync {
    fn get_revision(
        &self,
        scope: ExactScope,
        proxy_id: ProxyId,
        revision_id: ProxyRevisionId,
    ) -> Result<McpProxyRevision, ProxyError>;

    fn retire(&self, input: RetireProxy) -> Result<McpProxy, ProxyError>;
}

pub trait ProxyLifecycleStore: Send + Sync {
    fn transition(&self, input: TransitionProxyLifecycle) -> Result<McpProxy, ProxyError>;
    fn rotate_credentials(
        &self,
        input: RotateProxyCredentials,
    ) -> Result<McpProxyRevision, ProxyError>;
    fn rollback(&self, input: RollbackProxy) -> Result<McpProxy, ProxyError>;
    fn list_activity(&self, query: ListProxyActivity) -> Result<ListProxyActivityPage, ProxyError>;
}

pub trait ProxyStoreBackend: ProxyStore + ProxyRevisionStore + ProxyLifecycleStore {}
impl<T> ProxyStoreBackend for T where T: ProxyStore + ProxyRevisionStore + ProxyLifecycleStore {}

#[cfg(test)]
mod tests;
