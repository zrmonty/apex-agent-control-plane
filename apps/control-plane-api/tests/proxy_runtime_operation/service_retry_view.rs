//! Service-extension test view only. Never changes the persisted revision or
//! bypasses the PG publication gate; every method otherwise delegates to PG.
use apex_control_plane_api::*;
use std::sync::Arc;

pub(super) struct ApprovalReadView(pub Arc<PostgresProxyStore>);

impl ProxyRevisionStore for ApprovalReadView {
    fn get_revision(
        &self,
        scope: ExactScope,
        proxy: ProxyId,
        revision: ProxyRevisionId,
    ) -> Result<McpProxyRevision, ProxyError> {
        let mut revision = self.0.get_revision(scope, proxy, revision)?;
        revision.spec.governance_binding.approval_mode = ApprovalMode::Operator;
        Ok(revision)
    }
    fn retire(&self, input: RetireProxy) -> Result<McpProxy, ProxyError> {
        self.0.retire(input)
    }
}

impl ProxyStore for ApprovalReadView {
    fn create_with_outcome(&self, input: CreateProxy) -> Result<CreateProxyResult, ProxyError> {
        self.0.create_with_outcome(input)
    }
    fn update_draft(&self, input: UpdateProxyDraft) -> Result<McpProxy, ProxyError> {
        self.0.update_draft(input)
    }
    fn publish_revision(&self, input: PublishRevision) -> Result<McpProxyRevision, ProxyError> {
        self.0.publish_revision(input)
    }
    fn get(&self, scope: ExactScope, proxy: ProxyId) -> Result<McpProxy, ProxyError> {
        self.0.get(scope, proxy)
    }
    fn list(&self, input: ListProxies) -> Result<ListProxiesPage, ProxyError> {
        self.0.list(input)
    }
}

impl ProxyLifecycleStore for ApprovalReadView {
    fn transition(&self, input: TransitionProxyLifecycle) -> Result<McpProxy, ProxyError> {
        self.0.transition(input)
    }
    fn rotate_credentials(
        &self,
        input: RotateProxyCredentials,
    ) -> Result<McpProxyRevision, ProxyError> {
        self.0.rotate_credentials(input)
    }
    fn rollback(&self, input: RollbackProxy) -> Result<McpProxy, ProxyError> {
        self.0.rollback(input)
    }
    fn list_activity(&self, input: ListProxyActivity) -> Result<ListProxyActivityPage, ProxyError> {
        self.0.list_activity(input)
    }
}
