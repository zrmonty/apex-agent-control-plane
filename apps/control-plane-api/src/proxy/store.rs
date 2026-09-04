use super::{
    LifecycleCommand, McpProxyRevision, ProxyError, ProxyId, ProxyLifecycleState,
    ProxyRedactionStatus, ProxyRevisionId, ProxySpec,
};
use crate::ExactScope;

mod memory;
mod shared;
mod transitions;

#[cfg(feature = "postgres")]
mod postgres;

pub use memory::InMemoryProxyStore;
#[cfg(feature = "postgres")]
pub use postgres::PostgresProxyStore;

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
    fn create(&self, input: CreateProxy) -> Result<McpProxy, ProxyError>;
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
}

pub trait ProxyStoreBackend: ProxyStore + ProxyRevisionStore + ProxyLifecycleStore {}
impl<T> ProxyStoreBackend for T where T: ProxyStore + ProxyRevisionStore + ProxyLifecycleStore {}

#[cfg(test)]
mod tests;
