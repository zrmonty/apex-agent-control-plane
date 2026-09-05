use std::sync::Arc;

use tonic::{Request, Response, Status};

pub(super) use super::validate_proxy_spec;
pub(super) use super::{
    ApprovalMode, LifecycleCommand, MAX_SECRET_REFS, ProxyLifecycleState, ProxyRevisionId,
    ProxySpec, RollbackProxy, RotateProxyCredentials, SecretRef,
};
use super::{
    CreateProxy, ListProxies, ListProxyActivity, McpProxy, McpProxyRevision, ProxyError, ProxyId,
    ProxyStoreBackend, PublishRevision, TransitionProxyLifecycle, UpdateProxyDraft,
};
use crate::{ExactScope, OperatorCredentialResolver, OperatorTokenAuthenticator, proto};

mod operations;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLifecycleEvent {
    pub request_id: String,
    pub operation: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: Option<super::ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
}

pub trait ProxyRuntimeProvider: Send + Sync {
    fn reconcile(&self, revision: &McpProxyRevision) -> Result<(), ProxyError>;
    fn discover(
        &self,
        revision: &McpProxyRevision,
        upstream_id: &str,
    ) -> Result<proto::ProxyUpstreamDiscovery, ProxyError>;
    fn test_connection(
        &self,
        revision: &McpProxyRevision,
        upstream_id: &str,
    ) -> Result<proto::ProxyConnectionTest, ProxyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyApprovalRequest {
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: super::ProxyRevisionId,
    pub actor_id: String,
    pub action: String,
}

pub trait ProxyApprovalAuthority: Send + Sync {
    fn is_approved(&self, request: ProxyApprovalRequest) -> Result<bool, ProxyError>;
}

pub trait ProxyEventSink: Send + Sync {
    fn emit(&self, event: ProxyLifecycleEvent) -> Result<(), ProxyError>;
}

pub struct McpProxyService<R: OperatorCredentialResolver> {
    auth: Arc<OperatorTokenAuthenticator<R>>,
    store: Arc<dyn ProxyStoreBackend>,
    runtime: Option<Arc<dyn ProxyRuntimeProvider>>,
    events: Option<Arc<dyn ProxyEventSink>>,
    approvals: Option<Arc<dyn ProxyApprovalAuthority>>,
}

fn scope(workspace_id: String, namespace_id: String) -> ExactScope {
    ExactScope {
        workspace_id,
        namespace_id,
    }
}
fn validate_request_id(value: &str) -> Result<(), Status> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| invalid_status())?;
    if uuid.get_version_num() != 7 || uuid.hyphenated().to_string() != value {
        return Err(invalid_status());
    }
    Ok(())
}
fn parse_optional_revision(
    value: Option<String>,
) -> Result<Option<super::ProxyRevisionId>, Status> {
    value
        .map(super::ProxyRevisionId::new)
        .transpose()
        .map_err(proxy_status)
}
fn invalid_status() -> Status {
    Status::invalid_argument("INVALID_PROXY_REQUEST: request rejected safely")
}
fn internal_status<T>(_error: T) -> Status {
    Status::internal("PROXY_INTERNAL: request failed safely")
}

fn proxy_to_proto(proxy: McpProxy) -> proto::McpProxy {
    proto::McpProxy {
        proxy_id: proxy.proxy_id.to_string(),
        workspace_id: proxy.scope.workspace_id,
        namespace_id: proxy.scope.namespace_id,
        display_name: proxy.display_name,
        slug: proxy.slug,
        description: proxy.description,
        owner: proxy.owner,
        lifecycle_state: state_to_proto(proxy.lifecycle_state),
        redaction_status: redaction_to_proto(proxy.redaction_status),
        active_revision_id: proxy
            .active_revision_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        draft_revision_id: proxy
            .draft_revision_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        spec: proxy.spec.as_ref().map(super::wire::proxy_spec_to_proto),
    }
}

fn summary_to_proto(proxy: super::McpProxySummary) -> proto::McpProxySummary {
    proto::McpProxySummary {
        proxy_id: proxy.proxy_id.to_string(),
        display_name: proxy.display_name,
        slug: proxy.slug,
        workspace_id: proxy.scope.workspace_id,
        namespace_id: proxy.scope.namespace_id,
        lifecycle_state: state_to_proto(proxy.lifecycle_state),
        redaction_status: redaction_to_proto(proxy.redaction_status),
        active_revision_id: proxy
            .active_revision_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    }
}

fn revision_to_proto(revision: super::McpProxyRevision) -> proto::McpProxyRevision {
    proto::McpProxyRevision {
        revision_id: revision.revision_id.to_string(),
        proxy_id: revision.proxy_id.to_string(),
        config_hash: revision.config_hash,
        lifecycle_state: state_to_proto(revision.lifecycle_state),
        redaction_status: redaction_to_proto(revision.redaction_status),
        spec: Some(super::wire::proxy_spec_to_proto(&revision.spec)),
        created_by: revision.created_by,
        created_at: revision.created_at,
    }
}

fn activity_to_proto(activity: super::ProxyActivity) -> proto::McpProxyActivityEntry {
    proto::McpProxyActivityEntry {
        activity_id: activity.activity_id,
        proxy_id: activity.proxy_id.to_string(),
        revision_id: activity
            .revision_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        occurred_at: activity.occurred_at,
        actor_id: activity.actor_id.unwrap_or_default(),
        activity_type: activity.operation,
        reason_code: (!activity.reason_code.is_empty()).then_some(activity.reason_code),
        lifecycle_state: state_to_proto(activity.next_state),
        redaction_status: proto::McpProxyRedactionStatus::Redacted as i32,
        summary: activity.status,
        detail: None,
    }
}

fn state_to_proto(state: super::ProxyLifecycleState) -> i32 {
    use super::ProxyLifecycleState as State;
    match state {
        State::Draft => proto::McpProxyLifecycleState::Draft as i32,
        State::Validating => proto::McpProxyLifecycleState::Validating as i32,
        State::AwaitingApproval => proto::McpProxyLifecycleState::AwaitingApproval as i32,
        State::Provisioning => proto::McpProxyLifecycleState::Provisioning as i32,
        State::Ready => proto::McpProxyLifecycleState::Ready as i32,
        State::Degraded => proto::McpProxyLifecycleState::Degraded as i32,
        State::Paused => proto::McpProxyLifecycleState::Paused as i32,
        State::Retiring => proto::McpProxyLifecycleState::Retiring as i32,
        State::Retired => proto::McpProxyLifecycleState::Retired as i32,
        State::Failed => proto::McpProxyLifecycleState::Failed as i32,
    }
}

fn redaction_to_proto(status: super::ProxyRedactionStatus) -> i32 {
    match status {
        super::ProxyRedactionStatus::Redacted => proto::McpProxyRedactionStatus::Redacted as i32,
        super::ProxyRedactionStatus::PartiallyRedacted => {
            proto::McpProxyRedactionStatus::PartiallyRedacted as i32
        }
    }
}

fn proxy_status(error: impl std::fmt::Display) -> Status {
    let message = error.to_string();
    let code = message.split(':').next().unwrap_or_default();
    match code {
        "PROXY_NOT_FOUND" | "PROXY_REVISION_NOT_FOUND" => {
            Status::not_found("PROXY_NOT_FOUND: request rejected safely")
        }
        "PROXY_IDENTITY_CONFLICT" => {
            Status::already_exists("PROXY_IDENTITY_CONFLICT: request rejected safely")
        }
        "PROXY_REVISION_CONFLICT" => {
            Status::aborted("PROXY_REVISION_CONFLICT: request rejected safely")
        }
        "PROXY_RUNTIME_UNAVAILABLE"
        | "PROXY_EVENT_SINK_UNAVAILABLE"
        | "PROXY_ACTIVITY_UNAVAILABLE" => {
            Status::unavailable("PROXY_DEPENDENCY_UNAVAILABLE: request rejected safely")
        }
        "PROXY_APPROVAL_REQUIRED"
        | "INVALID_PROXY_LIFECYCLE_TRANSITION"
        | "IMMUTABLE_PROXY_REVISION" => {
            Status::failed_precondition("PROXY_PRECONDITION_FAILED: request rejected safely")
        }
        "PROXY_PROVIDER_FAILED" => {
            Status::unavailable("PROXY_PROVIDER_FAILED: request rejected safely")
        }
        _ => Status::invalid_argument("INVALID_PROXY_REQUEST: request rejected safely"),
    }
}

pub fn bounded_mcp_proxy_service_server<R: OperatorCredentialResolver>(
    service: McpProxyService<R>,
) -> proto::mcp_proxy_service_server::McpProxyServiceServer<McpProxyService<R>> {
    proto::mcp_proxy_service_server::McpProxyServiceServer::new(service)
        .max_decoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES)
}

#[tonic::async_trait]
impl<R: OperatorCredentialResolver> proto::mcp_proxy_service_server::McpProxyService
    for McpProxyService<R>
{
    async fn create_proxy(
        &self,
        request: Request<proto::CreateProxyRequest>,
    ) -> Result<Response<proto::CreateProxyResponse>, Status> {
        McpProxyService::create_proxy(self, request).await
    }

    async fn get_proxy(
        &self,
        request: Request<proto::GetProxyRequest>,
    ) -> Result<Response<proto::GetProxyResponse>, Status> {
        McpProxyService::get_proxy(self, request).await
    }
    async fn list_proxies(
        &self,
        request: Request<proto::ListProxiesRequest>,
    ) -> Result<Response<proto::ListProxiesResponse>, Status> {
        McpProxyService::list_proxies(self, request).await
    }
    async fn update_proxy_draft(
        &self,
        request: Request<proto::UpdateProxyDraftRequest>,
    ) -> Result<Response<proto::UpdateProxyDraftResponse>, Status> {
        McpProxyService::update_proxy_draft(self, request).await
    }
    async fn validate_proxy(
        &self,
        request: Request<proto::ValidateProxyRequest>,
    ) -> Result<Response<proto::ValidateProxyResponse>, Status> {
        McpProxyService::validate_proxy(self, request).await
    }
    async fn discover_upstream(
        &self,
        request: Request<proto::DiscoverUpstreamRequest>,
    ) -> Result<Response<proto::DiscoverUpstreamResponse>, Status> {
        McpProxyService::discover_upstream(self, request).await
    }
    async fn test_proxy_connection(
        &self,
        request: Request<proto::TestProxyConnectionRequest>,
    ) -> Result<Response<proto::TestProxyConnectionResponse>, Status> {
        McpProxyService::test_proxy_connection(self, request).await
    }
    async fn publish_proxy_revision(
        &self,
        request: Request<proto::PublishProxyRevisionRequest>,
    ) -> Result<Response<proto::PublishProxyRevisionResponse>, Status> {
        McpProxyService::publish_proxy_revision(self, request).await
    }
    async fn deploy_proxy(
        &self,
        request: Request<proto::DeployProxyRequest>,
    ) -> Result<Response<proto::DeployProxyResponse>, Status> {
        McpProxyService::deploy_proxy(self, request).await
    }
    async fn pause_proxy(
        &self,
        request: Request<proto::PauseProxyRequest>,
    ) -> Result<Response<proto::PauseProxyResponse>, Status> {
        McpProxyService::pause_proxy(self, request).await
    }
    async fn resume_proxy(
        &self,
        request: Request<proto::ResumeProxyRequest>,
    ) -> Result<Response<proto::ResumeProxyResponse>, Status> {
        McpProxyService::resume_proxy(self, request).await
    }
    async fn rotate_proxy_credentials(
        &self,
        request: Request<proto::RotateProxyCredentialsRequest>,
    ) -> Result<Response<proto::RotateProxyCredentialsResponse>, Status> {
        McpProxyService::rotate_proxy_credentials(self, request).await
    }
    async fn rollback_proxy(
        &self,
        request: Request<proto::RollbackProxyRequest>,
    ) -> Result<Response<proto::RollbackProxyResponse>, Status> {
        McpProxyService::rollback_proxy(self, request).await
    }
    async fn retire_proxy(
        &self,
        request: Request<proto::RetireProxyRequest>,
    ) -> Result<Response<proto::RetireProxyResponse>, Status> {
        McpProxyService::retire_proxy(self, request).await
    }
    async fn list_proxy_activity(
        &self,
        request: Request<proto::ListProxyActivityRequest>,
    ) -> Result<Response<proto::ListProxyActivityResponse>, Status> {
        McpProxyService::list_proxy_activity(self, request).await
    }
    async fn get_proxy_capabilities(
        &self,
        _request: Request<proto::GetProxyCapabilitiesRequest>,
    ) -> Result<Response<proto::GetProxyCapabilitiesResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn list_proxy_revisions(
        &self,
        _request: Request<proto::ListProxyRevisionsRequest>,
    ) -> Result<Response<proto::ListProxyRevisionsResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn get_proxy_operation(
        &self,
        _request: Request<proto::GetProxyOperationRequest>,
    ) -> Result<Response<proto::GetProxyOperationResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn list_proxy_bindings(
        &self,
        _request: Request<proto::ListProxyBindingsRequest>,
    ) -> Result<Response<proto::ListProxyBindingsResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn list_proxy_approvals(
        &self,
        _request: Request<proto::ListProxyApprovalsRequest>,
    ) -> Result<Response<proto::ListProxyApprovalsResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn decide_proxy_approval(
        &self,
        _request: Request<proto::DecideProxyApprovalRequest>,
    ) -> Result<Response<proto::DecideProxyApprovalResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
    async fn get_proxy_trace(
        &self,
        _request: Request<proto::GetProxyTraceRequest>,
    ) -> Result<Response<proto::GetProxyTraceResponse>, Status> {
        Err(Status::unimplemented("managed capability is not wired"))
    }
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
