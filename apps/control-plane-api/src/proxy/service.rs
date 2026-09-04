use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::{
    CreateProxy, ListProxies, McpProxy, ProxyError, ProxyId, ProxyStoreBackend,
    PublishRevision, TransitionProxyLifecycle, UpdateProxyDraft,
};
use crate::{ExactScope, OperatorCredentialResolver, OperatorTokenAuthenticator, proto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLifecycleEvent {
    pub operation: String,
    pub scope: ExactScope,
    pub proxy_id: ProxyId,
    pub revision_id: Option<super::ProxyRevisionId>,
    pub actor_id: String,
    pub reason_code: String,
}

pub trait ProxyRuntimeProvider: Send + Sync {
    fn reconcile(&self, proxy: &McpProxy) -> Result<(), ProxyError>;
}

pub trait ProxyEventSink: Send + Sync {
    fn emit(&self, event: ProxyLifecycleEvent) -> Result<(), ProxyError>;
}

pub struct McpProxyService<R: OperatorCredentialResolver> {
    auth: Arc<OperatorTokenAuthenticator<R>>,
    store: Arc<dyn ProxyStoreBackend>,
    runtime: Option<Arc<dyn ProxyRuntimeProvider>>,
    events: Option<Arc<dyn ProxyEventSink>>,
}

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    pub fn new(auth: OperatorTokenAuthenticator<R>, store: Arc<dyn ProxyStoreBackend>) -> Self {
        Self {
            auth: Arc::new(auth),
            store,
            runtime: None,
            events: None,
        }
    }

    pub fn from_store<S>(auth: OperatorTokenAuthenticator<R>, store: Arc<S>) -> Self
    where S: ProxyStoreBackend + 'static {
        Self::new(auth, store)
    }

    pub fn with_runtime_provider(mut self, runtime: Arc<dyn ProxyRuntimeProvider>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_event_sink(mut self, events: Arc<dyn ProxyEventSink>) -> Self {
        self.events = Some(events);
        self
    }

    fn authenticate_scope<T>(&self, request: &Request<T>, scope: &ExactScope) -> Result<String, Status> {
        let operator = self.auth.authenticate(request.metadata()).map_err(proxy_status)?;
        if !operator.allows_scope(&scope.workspace_id, &scope.namespace_id) {
            return Err(Status::permission_denied("PROXY_SCOPE_DENIED: request rejected safely"));
        }
        Ok(operator.subject().to_owned())
    }

    pub async fn create_proxy(
        &self,
        request: Request<proto::CreateProxyRequest>,
    ) -> Result<Response<proto::CreateProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = ExactScope {
            workspace_id: input.workspace_id.clone(),
            namespace_id: input.namespace_id.clone(),
        };
        self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || {
            store.create(CreateProxy {
                request_id: input.request_id,
                scope,
                proxy_id,
                display_name: input.display_name,
                slug: input.slug,
                description: input.description,
                owner: input.owner,
            })
        })
        .await
        .map_err(|_| Status::internal("PROXY_INTERNAL: request failed safely"))?
        .map_err(proxy_status)?;
        Ok(Response::new(proto::CreateProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
            duplicate: false,
        }))
    }

    pub async fn get_proxy(&self, request: Request<proto::GetProxyRequest>) -> Result<Response<proto::GetProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || store.get(scope, proxy_id)).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(Response::new(proto::GetProxyResponse { proxy: Some(proxy_to_proto(proxy)) }))
    }

    pub async fn list_proxies(&self, request: Request<proto::ListProxiesRequest>) -> Result<Response<proto::ListProxiesResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let page_size = usize::try_from(input.page_size).map_err(|_| invalid_status())?;
        let page_token = input.page_token.clone();
        let store = Arc::clone(&self.store);
        let page = tokio::task::spawn_blocking(move || store.list(ListProxies { scope, page_size, page_token })).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(Response::new(proto::ListProxiesResponse {
            proxies: page.proxies.into_iter().map(summary_to_proto).collect(),
            next_page_token: page.next_page_token,
        }))
    }

    pub async fn update_proxy_draft(&self, request: Request<proto::UpdateProxyDraftRequest>) -> Result<Response<proto::UpdateProxyDraftResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let expected_revision_id = parse_optional_revision(input.expected_revision_id)?;
        let spec = input.draft.ok_or_else(invalid_status)?.try_into().map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || store.update_draft(UpdateProxyDraft { request_id: input.request_id, scope, proxy_id, expected_revision_id, actor_id, spec })).await.map_err(internal_status)?.map_err(proxy_status)?;
        let revision = proxy.draft_revision_id.clone().ok_or_else(|| internal_status(()))?;
        let store = Arc::clone(&self.store);
        let revision_scope = proxy.scope.clone();
        let revision_proxy_id = proxy.proxy_id.clone();
        let revision = tokio::task::spawn_blocking(move || store.get_revision(revision_scope, revision_proxy_id, revision)).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(Response::new(proto::UpdateProxyDraftResponse { proxy: Some(proxy_to_proto(proxy)), revision: Some(revision_to_proto(revision)) }))
    }

    pub async fn publish_proxy_revision(&self, request: Request<proto::PublishProxyRevisionRequest>) -> Result<Response<proto::PublishProxyRevisionResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let draft_revision_id = super::ProxyRevisionId::new(input.draft_revision_id).map_err(proxy_status)?;
        let expected_revision_id = parse_optional_revision(input.expected_revision_id)?;
        let store = Arc::clone(&self.store);
        let revision = tokio::task::spawn_blocking(move || store.publish_revision(PublishRevision { request_id: input.request_id, scope, proxy_id, draft_revision_id, expected_revision_id, actor_id })).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(Response::new(proto::PublishProxyRevisionResponse { revision: Some(revision_to_proto(revision)) }))
    }

    async fn lifecycle(&self, scope: ExactScope, actor_id: String, request_id: String, proxy_id: ProxyId, revision_id: super::ProxyRevisionId, expected_revision_id: Option<super::ProxyRevisionId>, reason_code: String, command: super::LifecycleCommand, approved: bool) -> Result<McpProxy, Status> {
        let event = ProxyLifecycleEvent { operation: command.operation().to_owned(), scope: scope.clone(), proxy_id: proxy_id.clone(), revision_id: Some(revision_id.clone()), actor_id: actor_id.clone(), reason_code: reason_code.clone() };
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || store.transition(TransitionProxyLifecycle { request_id, scope, proxy_id, revision_id, expected_revision_id, actor_id, reason_code, command, approved })).await.map_err(internal_status)?.map_err(proxy_status)?;
        if let Some(events) = &self.events { events.emit(event).map_err(proxy_status)?; }
        Ok(proxy)
    }

    async fn reconciled(&self, proxy: McpProxy) -> Result<McpProxy, Status> {
        let Some(runtime) = &self.runtime else { return Err(Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")); };
        let runtime = Arc::clone(runtime);
        let copy = proxy.clone();
        tokio::task::spawn_blocking(move || runtime.reconcile(&copy)).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(proxy)
    }

    pub async fn validate_proxy(&self, request: Request<proto::ValidateProxyRequest>) -> Result<Response<proto::ValidateProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?; let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?; let revision_id = parse_optional_revision(input.expected_revision_id)?.ok_or_else(invalid_status)?;
        let spec: super::ProxySpec = input.draft.ok_or_else(invalid_status)?.try_into().map_err(proxy_status)?; super::validate_proxy_spec(&spec).map_err(proxy_status)?;
        self.lifecycle(scope.clone(), actor_id.clone(), input.request_id.clone(), proxy_id.clone(), revision_id.clone(), Some(revision_id.clone()), "proxy.validation_started".to_owned(), super::LifecycleCommand::Validate, false).await?;
        self.lifecycle(scope, actor_id, input.request_id, proxy_id, revision_id.clone(), Some(revision_id), "proxy.validation_succeeded".to_owned(), super::LifecycleCommand::ValidationSucceeded, false).await?;
        Ok(Response::new(proto::ValidateProxyResponse { report: Some(proto::ProxyValidationReport { valid: true, error_messages: vec![], warning_messages: vec![], validation_id: "validated".to_owned(), redaction_status: proto::McpProxyRedactionStatus::Redacted as i32 }) }))
    }

    pub async fn deploy_proxy(&self, request: Request<proto::DeployProxyRequest>) -> Result<Response<proto::DeployProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); let actor = self.authenticate_scope(&request, &scope)?; let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?; let revision_id = super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?; let expected = parse_optional_revision(input.expected_revision_id)?;
        let store = Arc::clone(&self.store); let revision_scope = scope.clone(); let revision_proxy = proxy_id.clone(); let revision_copy = revision_id.clone();
        let revision = tokio::task::spawn_blocking(move || store.get_revision(revision_scope, revision_proxy, revision_copy)).await.map_err(internal_status)?.map_err(proxy_status)?;
        let approved = revision.spec.governance_binding.approval_mode == super::ApprovalMode::None;
        if self.runtime.is_none() { return Err(Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")); }
        let proxy = self.lifecycle(scope, actor, input.request_id, proxy_id, revision_id, expected, "proxy.deploy".to_owned(), super::LifecycleCommand::Deploy, approved).await?;
        Ok(Response::new(proto::DeployProxyResponse { proxy: Some(proxy_to_proto(self.reconciled(proxy).await?)) }))
    }

    pub async fn pause_proxy(&self, request: Request<proto::PauseProxyRequest>) -> Result<Response<proto::PauseProxyResponse>, Status> { self.pause_or_resume(request, super::LifecycleCommand::Pause).await }
    pub async fn resume_proxy(&self, request: Request<proto::ResumeProxyRequest>) -> Result<Response<proto::ResumeProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); let actor = self.authenticate_scope(&request, &scope)?; let input = request.into_inner();
        if self.runtime.is_none() { return Err(Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")); }
        let proxy = self.lifecycle(scope, actor, input.request_id, ProxyId::new(input.proxy_id).map_err(proxy_status)?, super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?, parse_optional_revision(input.expected_revision_id)?, "proxy.resume".to_owned(), super::LifecycleCommand::Resume, false).await?;
        Ok(Response::new(proto::ResumeProxyResponse { proxy: Some(proxy_to_proto(self.reconciled(proxy).await?)) }))
    }

    async fn pause_or_resume(&self, request: Request<proto::PauseProxyRequest>, command: super::LifecycleCommand) -> Result<Response<proto::PauseProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); let actor = self.authenticate_scope(&request, &scope)?; let input = request.into_inner();
        if self.runtime.is_none() { return Err(Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")); }
        let reason = input.reason_code.unwrap_or_else(|| "proxy.pause".to_owned());
        let proxy = self.lifecycle(scope, actor, input.request_id, ProxyId::new(input.proxy_id).map_err(proxy_status)?, super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?, parse_optional_revision(input.expected_revision_id)?, reason, command, false).await?;
        Ok(Response::new(proto::PauseProxyResponse { proxy: Some(proxy_to_proto(self.reconciled(proxy).await?)) }))
    }

    async fn require_revision(&self, scope: ExactScope, proxy_id: ProxyId, revision_id: super::ProxyRevisionId) -> Result<super::McpProxyRevision, Status> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.get_revision(scope, proxy_id, revision_id)).await.map_err(internal_status)?.map_err(proxy_status)
    }

    pub async fn discover_upstream(&self, request: Request<proto::DiscoverUpstreamRequest>) -> Result<Response<proto::DiscoverUpstreamResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?; let revision_id = super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        let revision = self.require_revision(scope, proxy_id, revision_id).await?;
        let upstream = revision.spec.upstreams.into_iter().find(|value| value.upstream_id == input.upstream_id).ok_or_else(invalid_status)?;
        Ok(Response::new(proto::DiscoverUpstreamResponse { discovery: Some(proto::ProxyUpstreamDiscovery { upstream_id: upstream.upstream_id, server_identity: upstream.server_identity, discovered_tools: vec![], discovered_resources: vec![], discovered_prompts: vec![], schema_hash: upstream.tool_catalog_hash.unwrap_or_default(), redaction_status: proto::McpProxyRedactionStatus::Redacted as i32 }) }))
    }

    pub async fn test_proxy_connection(&self, request: Request<proto::TestProxyConnectionRequest>) -> Result<Response<proto::TestProxyConnectionResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?; let revision_id = super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        let revision = self.require_revision(scope, proxy_id, revision_id).await?;
        let upstream = revision.spec.upstreams.into_iter().find(|value| value.upstream_id == input.upstream_id).ok_or_else(invalid_status)?;
        Ok(Response::new(proto::TestProxyConnectionResponse { result: Some(proto::ProxyConnectionTest { connected: false, upstream_id: upstream.upstream_id, server_identity: upstream.server_identity, summary: "Runtime connection tests require a configured provider.".to_owned(), redaction_status: proto::McpProxyRedactionStatus::Redacted as i32 }) }))
    }

    pub async fn rotate_proxy_credentials(&self, request: Request<proto::RotateProxyCredentialsRequest>) -> Result<Response<proto::RotateProxyCredentialsResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); self.authenticate_scope(&request, &scope)?;
        if input.secret_refs.len() > super::MAX_SECRET_REFS || input.secret_refs.iter().any(|value| super::SecretRef::new(value).is_err()) { return Err(invalid_status()); }
        let revision = self.require_revision(scope, ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?, super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?).await?;
        Ok(Response::new(proto::RotateProxyCredentialsResponse { revision: Some(revision_to_proto(revision)) }))
    }

    pub async fn rollback_proxy(&self, request: Request<proto::RollbackProxyRequest>) -> Result<Response<proto::RollbackProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?; let target = super::ProxyRevisionId::new(input.target_revision_id.clone()).map_err(proxy_status)?;
        let revision = self.require_revision(scope.clone(), proxy_id.clone(), target.clone()).await?;
        if revision.lifecycle_state != super::ProxyLifecycleState::Ready { return Err(Status::failed_precondition("PROXY_ROLLBACK_TARGET_NOT_READY: request rejected safely")); }
        let store = Arc::clone(&self.store); let proxy = tokio::task::spawn_blocking(move || store.get(scope, proxy_id)).await.map_err(internal_status)?.map_err(proxy_status)?;
        if proxy.active_revision_id.as_ref() != Some(&target) { return Err(Status::failed_precondition("PROXY_ROLLBACK_REQUIRES_RECONCILER: request rejected safely")); }
        Ok(Response::new(proto::RollbackProxyResponse { proxy: Some(proxy_to_proto(proxy)) }))
    }

    pub async fn retire_proxy(&self, request: Request<proto::RetireProxyRequest>) -> Result<Response<proto::RetireProxyResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); let actor = self.authenticate_scope(&request, &scope)?; let input = request.into_inner();
        if self.runtime.is_none() { return Err(Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")); }
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?; let revision_id = super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?; let expected = parse_optional_revision(input.expected_revision_id)?;
        let reason = input.reason_code.unwrap_or_else(|| "proxy.retire".to_owned());
        let proxy = self.lifecycle(scope.clone(), actor.clone(), input.request_id.clone(), proxy_id.clone(), revision_id.clone(), expected.clone(), reason.clone(), super::LifecycleCommand::Retire, false).await?;
        self.reconciled(proxy).await?;
        let proxy = self.lifecycle(scope, actor, input.request_id, proxy_id, revision_id, expected, reason, super::LifecycleCommand::Retired, false).await?;
        Ok(Response::new(proto::RetireProxyResponse { proxy: Some(proxy_to_proto(proxy)) }))
    }

    pub async fn list_proxy_activity(&self, request: Request<proto::ListProxyActivityRequest>) -> Result<Response<proto::ListProxyActivityResponse>, Status> {
        let input = request.get_ref(); let scope = scope(input.workspace_id.clone(), input.namespace_id.clone()); self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.get(scope, proxy_id)).await.map_err(internal_status)?.map_err(proxy_status)?;
        Ok(Response::new(proto::ListProxyActivityResponse { activity: vec![], next_page_token: String::new() }))
    }
}

fn scope(workspace_id: String, namespace_id: String) -> ExactScope { ExactScope { workspace_id, namespace_id } }
fn parse_optional_revision(value: Option<String>) -> Result<Option<super::ProxyRevisionId>, Status> { value.map(super::ProxyRevisionId::new).transpose().map_err(proxy_status) }
fn invalid_status() -> Status { Status::invalid_argument("INVALID_PROXY_REQUEST: request rejected safely") }
fn internal_status<T>(_error: T) -> Status { Status::internal("PROXY_INTERNAL: request failed safely") }

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
        active_revision_id: proxy.active_revision_id.map(|id| id.to_string()).unwrap_or_default(),
        draft_revision_id: proxy.draft_revision_id.map(|id| id.to_string()).unwrap_or_default(),
        spec: None,
    }
}

fn summary_to_proto(proxy: super::McpProxySummary) -> proto::McpProxySummary {
    proto::McpProxySummary { proxy_id: proxy.proxy_id.to_string(), display_name: proxy.display_name, slug: proxy.slug, workspace_id: proxy.scope.workspace_id, namespace_id: proxy.scope.namespace_id, lifecycle_state: state_to_proto(proxy.lifecycle_state), redaction_status: redaction_to_proto(proxy.redaction_status), active_revision_id: proxy.active_revision_id.map(|id| id.to_string()).unwrap_or_default() }
}

fn revision_to_proto(revision: super::McpProxyRevision) -> proto::McpProxyRevision {
    proto::McpProxyRevision { revision_id: revision.revision_id.to_string(), proxy_id: revision.proxy_id.to_string(), config_hash: revision.config_hash, lifecycle_state: state_to_proto(revision.lifecycle_state), redaction_status: redaction_to_proto(revision.redaction_status), spec: None, created_by: revision.created_by, created_at: revision.created_at }
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
    let _ = error;
    Status::invalid_argument("INVALID_PROXY_REQUEST: request rejected safely")
}

pub fn bounded_mcp_proxy_service_server<R: OperatorCredentialResolver>(service: McpProxyService<R>) -> proto::mcp_proxy_service_server::McpProxyServiceServer<McpProxyService<R>> {
    proto::mcp_proxy_service_server::McpProxyServiceServer::new(service)
        .max_decoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES)
}

#[tonic::async_trait]
impl<R: OperatorCredentialResolver> proto::mcp_proxy_service_server::McpProxyService for McpProxyService<R> {
    async fn create_proxy(&self, request: Request<proto::CreateProxyRequest>) -> Result<Response<proto::CreateProxyResponse>, Status> {
        McpProxyService::create_proxy(self, request).await
    }

    async fn get_proxy(&self, request: Request<proto::GetProxyRequest>) -> Result<Response<proto::GetProxyResponse>, Status> { McpProxyService::get_proxy(self, request).await }
    async fn list_proxies(&self, request: Request<proto::ListProxiesRequest>) -> Result<Response<proto::ListProxiesResponse>, Status> { McpProxyService::list_proxies(self, request).await }
    async fn update_proxy_draft(&self, request: Request<proto::UpdateProxyDraftRequest>) -> Result<Response<proto::UpdateProxyDraftResponse>, Status> { McpProxyService::update_proxy_draft(self, request).await }
    async fn validate_proxy(&self, request: Request<proto::ValidateProxyRequest>) -> Result<Response<proto::ValidateProxyResponse>, Status> { McpProxyService::validate_proxy(self, request).await }
    async fn discover_upstream(&self, request: Request<proto::DiscoverUpstreamRequest>) -> Result<Response<proto::DiscoverUpstreamResponse>, Status> { McpProxyService::discover_upstream(self, request).await }
    async fn test_proxy_connection(&self, request: Request<proto::TestProxyConnectionRequest>) -> Result<Response<proto::TestProxyConnectionResponse>, Status> { McpProxyService::test_proxy_connection(self, request).await }
    async fn publish_proxy_revision(&self, request: Request<proto::PublishProxyRevisionRequest>) -> Result<Response<proto::PublishProxyRevisionResponse>, Status> { McpProxyService::publish_proxy_revision(self, request).await }
    async fn deploy_proxy(&self, request: Request<proto::DeployProxyRequest>) -> Result<Response<proto::DeployProxyResponse>, Status> { McpProxyService::deploy_proxy(self, request).await }
    async fn pause_proxy(&self, request: Request<proto::PauseProxyRequest>) -> Result<Response<proto::PauseProxyResponse>, Status> { McpProxyService::pause_proxy(self, request).await }
    async fn resume_proxy(&self, request: Request<proto::ResumeProxyRequest>) -> Result<Response<proto::ResumeProxyResponse>, Status> { McpProxyService::resume_proxy(self, request).await }
    async fn rotate_proxy_credentials(&self, request: Request<proto::RotateProxyCredentialsRequest>) -> Result<Response<proto::RotateProxyCredentialsResponse>, Status> { McpProxyService::rotate_proxy_credentials(self, request).await }
    async fn rollback_proxy(&self, request: Request<proto::RollbackProxyRequest>) -> Result<Response<proto::RollbackProxyResponse>, Status> { McpProxyService::rollback_proxy(self, request).await }
    async fn retire_proxy(&self, request: Request<proto::RetireProxyRequest>) -> Result<Response<proto::RetireProxyResponse>, Status> { McpProxyService::retire_proxy(self, request).await }
    async fn list_proxy_activity(&self, request: Request<proto::ListProxyActivityRequest>) -> Result<Response<proto::ListProxyActivityResponse>, Status> { McpProxyService::list_proxy_activity(self, request).await }
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
