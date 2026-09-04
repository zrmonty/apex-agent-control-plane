use super::*;

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    pub(super) fn require_event_sink(&self) -> Result<Arc<dyn ProxyEventSink>, Status> {
        self.events
            .clone()
            .ok_or_else(|| proxy_status(ProxyError::event_sink_unavailable()))
    }

    pub(super) fn emit_event(&self, event: ProxyLifecycleEvent) -> Result<(), Status> {
        self.require_event_sink()?.emit(event).map_err(proxy_status)
    }

    pub fn new(auth: OperatorTokenAuthenticator<R>, store: Arc<dyn ProxyStoreBackend>) -> Self {
        Self {
            auth: Arc::new(auth),
            store,
            runtime: None,
            events: None,
            approvals: None,
        }
    }

    pub fn from_store<S>(auth: OperatorTokenAuthenticator<R>, store: Arc<S>) -> Self
    where
        S: ProxyStoreBackend + 'static,
    {
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

    pub fn with_approval_authority(mut self, approvals: Arc<dyn ProxyApprovalAuthority>) -> Self {
        self.approvals = Some(approvals);
        self
    }

    fn authenticate_scope<T>(
        &self,
        request: &Request<T>,
        scope: &ExactScope,
    ) -> Result<String, Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(|error| error.into_status())?;
        if !operator.allows_scope(&scope.workspace_id, &scope.namespace_id) {
            return Err(Status::permission_denied(
                "PROXY_SCOPE_DENIED: request rejected safely",
            ));
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
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let _events = self.require_event_sink()?;
        let input = request.into_inner();
        let request_id = input.request_id.clone();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let outcome = tokio::task::spawn_blocking(move || {
            store.create_with_outcome(CreateProxy {
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
        self.emit_event(ProxyLifecycleEvent {
            request_id,
            operation: "create_proxy".to_owned(),
            scope: outcome.proxy.scope.clone(),
            proxy_id: outcome.proxy.proxy_id.clone(),
            revision_id: None,
            actor_id,
            reason_code: "proxy.created".to_owned(),
        })?;
        Ok(Response::new(proto::CreateProxyResponse {
            proxy: Some(proxy_to_proto(outcome.proxy)),
            duplicate: outcome.duplicate,
        }))
    }

    pub async fn get_proxy(
        &self,
        request: Request<proto::GetProxyRequest>,
    ) -> Result<Response<proto::GetProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || store.get(scope, proxy_id))
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)?;
        Ok(Response::new(proto::GetProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    pub async fn list_proxies(
        &self,
        request: Request<proto::ListProxiesRequest>,
    ) -> Result<Response<proto::ListProxiesResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let page_size = usize::try_from(input.page_size).map_err(|_| invalid_status())?;
        let page_token = input.page_token.clone();
        let store = Arc::clone(&self.store);
        let page = tokio::task::spawn_blocking(move || {
            store.list(ListProxies {
                scope,
                page_size,
                page_token,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        Ok(Response::new(proto::ListProxiesResponse {
            proxies: page.proxies.into_iter().map(summary_to_proto).collect(),
            next_page_token: page.next_page_token,
        }))
    }

    pub async fn update_proxy_draft(
        &self,
        request: Request<proto::UpdateProxyDraftRequest>,
    ) -> Result<Response<proto::UpdateProxyDraftResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let _events = self.require_event_sink()?;
        let input = request.into_inner();
        let request_id = input.request_id.clone();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let expected_revision_id = parse_optional_revision(input.expected_revision_id)?;
        let spec = input
            .draft
            .ok_or_else(invalid_status)?
            .try_into()
            .map_err(proxy_status)?;
        let store_actor = actor_id.clone();
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || {
            store.update_draft(UpdateProxyDraft {
                request_id: input.request_id,
                scope,
                proxy_id,
                expected_revision_id,
                actor_id: store_actor,
                spec,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        let revision = proxy
            .draft_revision_id
            .clone()
            .ok_or_else(|| internal_status(()))?;
        let store = Arc::clone(&self.store);
        let revision_scope = proxy.scope.clone();
        let revision_proxy_id = proxy.proxy_id.clone();
        let revision = tokio::task::spawn_blocking(move || {
            store.get_revision(revision_scope, revision_proxy_id, revision)
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        self.emit_event(ProxyLifecycleEvent {
            request_id,
            operation: "update_proxy_draft".to_owned(),
            scope: proxy.scope.clone(),
            proxy_id: proxy.proxy_id.clone(),
            revision_id: Some(revision.revision_id.clone()),
            actor_id,
            reason_code: "proxy.draft_updated".to_owned(),
        })?;
        Ok(Response::new(proto::UpdateProxyDraftResponse {
            proxy: Some(proxy_to_proto(proxy)),
            revision: Some(revision_to_proto(revision)),
        }))
    }

    pub async fn publish_proxy_revision(
        &self,
        request: Request<proto::PublishProxyRevisionRequest>,
    ) -> Result<Response<proto::PublishProxyRevisionResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let _events = self.require_event_sink()?;
        let input = request.into_inner();
        let request_id = input.request_id.clone();
        let event_scope = scope.clone();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let draft_revision_id =
            super::ProxyRevisionId::new(input.draft_revision_id).map_err(proxy_status)?;
        let expected_revision_id = parse_optional_revision(input.expected_revision_id)?;
        let store_actor = actor_id.clone();
        let store = Arc::clone(&self.store);
        let revision = tokio::task::spawn_blocking(move || {
            store.publish_revision(PublishRevision {
                request_id: input.request_id,
                scope,
                proxy_id,
                draft_revision_id,
                expected_revision_id,
                actor_id: store_actor,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        self.emit_event(ProxyLifecycleEvent {
            request_id,
            operation: "publish_proxy_revision".to_owned(),
            scope: event_scope,
            proxy_id: revision.proxy_id.clone(),
            revision_id: Some(revision.revision_id.clone()),
            actor_id,
            reason_code: "proxy.revision_published".to_owned(),
        })?;
        Ok(Response::new(proto::PublishProxyRevisionResponse {
            revision: Some(revision_to_proto(revision)),
        }))
    }
}

mod inspection;
mod lifecycle;
