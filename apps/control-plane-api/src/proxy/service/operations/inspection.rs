use super::super::*;

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    pub async fn discover_upstream(
        &self,
        request: Request<proto::DiscoverUpstreamRequest>,
    ) -> Result<Response<proto::DiscoverUpstreamResponse>, Status> {
        let input = request.get_ref();
        validate_request_id(&input.request_id)?;
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let revision_id =
            super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        let revision = self.require_revision(scope, proxy_id, revision_id).await?;
        let Some(runtime) = &self.runtime else {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        };
        let runtime = Arc::clone(runtime);
        let upstream_id = input.upstream_id.clone();
        let discovery =
            tokio::task::spawn_blocking(move || runtime.discover(&revision, &upstream_id))
                .await
                .map_err(internal_status)?
                .map_err(proxy_status)?;
        Ok(Response::new(proto::DiscoverUpstreamResponse {
            discovery: Some(discovery),
        }))
    }

    pub async fn test_proxy_connection(
        &self,
        request: Request<proto::TestProxyConnectionRequest>,
    ) -> Result<Response<proto::TestProxyConnectionResponse>, Status> {
        let input = request.get_ref();
        validate_request_id(&input.request_id)?;
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let revision_id =
            super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        let revision = self.require_revision(scope, proxy_id, revision_id).await?;
        let Some(runtime) = &self.runtime else {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        };
        let runtime = Arc::clone(runtime);
        let upstream_id = input.upstream_id.clone();
        let result =
            tokio::task::spawn_blocking(move || runtime.test_connection(&revision, &upstream_id))
                .await
                .map_err(internal_status)?
                .map_err(proxy_status)?;
        Ok(Response::new(proto::TestProxyConnectionResponse {
            result: Some(result),
        }))
    }

    pub async fn rotate_proxy_credentials(
        &self,
        request: Request<proto::RotateProxyCredentialsRequest>,
    ) -> Result<Response<proto::RotateProxyCredentialsResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let Some(_) = &self.events else {
            return Err(Status::failed_precondition(
                "PROXY_EVENT_SINK_UNAVAILABLE: request rejected safely",
            ));
        };
        if input.secret_refs.is_empty()
            || input.secret_refs.len() > super::MAX_SECRET_REFS
            || input
                .secret_refs
                .iter()
                .any(|value| super::SecretRef::new(value).is_err())
        {
            return Err(invalid_status());
        }
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let revision_id =
            super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        if self.runtime.is_none() {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        }
        let secret_refs = input
            .secret_refs
            .iter()
            .cloned()
            .map(super::SecretRef::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let request_id = input.request_id.clone();
        let expected = parse_optional_revision(input.expected_revision_id.clone())?;
        let reason = input
            .reason_code
            .clone()
            .unwrap_or_else(|| "proxy.rotate_credentials".to_owned());
        let store_scope = scope.clone();
        let store_proxy_id = proxy_id.clone();
        let store_revision_id = revision_id.clone();
        let store_actor = actor.clone();
        let store_reason = reason.clone();
        let revision = tokio::task::spawn_blocking(move || {
            store.rotate_credentials(super::RotateProxyCredentials {
                request_id,
                scope: store_scope,
                proxy_id: store_proxy_id,
                revision_id: store_revision_id,
                expected_revision_id: expected,
                actor_id: store_actor,
                reason_code: store_reason,
                secret_refs,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        self.reconciled(revision.clone()).await?;
        self.events
            .as_ref()
            .expect("checked above")
            .emit(ProxyLifecycleEvent {
                request_id: input.request_id.clone(),
                operation: "rotate_proxy_credentials".to_owned(),
                scope,
                proxy_id,
                revision_id: Some(revision.revision_id.clone()),
                actor_id: actor,
                reason_code: reason,
            })
            .map_err(proxy_status)?;
        Ok(Response::new(proto::RotateProxyCredentialsResponse {
            revision: Some(revision_to_proto(revision)),
        }))
    }

    pub async fn rollback_proxy(
        &self,
        request: Request<proto::RollbackProxyRequest>,
    ) -> Result<Response<proto::RollbackProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let Some(_) = &self.events else {
            return Err(Status::failed_precondition(
                "PROXY_EVENT_SINK_UNAVAILABLE: request rejected safely",
            ));
        };
        if self.runtime.is_none() {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        }
        validate_request_id(&input.request_id)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let revision_id =
            super::ProxyRevisionId::new(input.revision_id.clone()).map_err(proxy_status)?;
        let target =
            super::ProxyRevisionId::new(input.target_revision_id.clone()).map_err(proxy_status)?;
        let target_revision = self
            .require_revision(scope.clone(), proxy_id.clone(), target.clone())
            .await?;
        if target_revision.lifecycle_state != super::ProxyLifecycleState::Ready {
            return Err(Status::failed_precondition(
                "PROXY_ROLLBACK_TARGET_NOT_READY: request rejected safely",
            ));
        }
        self.reconciled(target_revision).await?;
        let expected = parse_optional_revision(input.expected_revision_id.clone())?;
        let reason = input
            .reason_code
            .clone()
            .unwrap_or_else(|| "proxy.rollback".to_owned());
        let store = Arc::clone(&self.store);
        let request_id = input.request_id.clone();
        let scope_copy = scope.clone();
        let proxy_copy = proxy_id.clone();
        let revision_copy = revision_id.clone();
        let target_copy = target.clone();
        let actor_copy = actor.clone();
        let reason_copy = reason.clone();
        let proxy = tokio::task::spawn_blocking(move || {
            store.rollback(super::RollbackProxy {
                request_id,
                scope: scope_copy,
                proxy_id: proxy_copy,
                revision_id: revision_copy,
                target_revision_id: target_copy,
                expected_revision_id: expected,
                actor_id: actor_copy,
                reason_code: reason_copy,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        self.events
            .as_ref()
            .expect("checked above")
            .emit(ProxyLifecycleEvent {
                request_id: input.request_id.clone(),
                operation: "rollback_proxy".to_owned(),
                scope,
                proxy_id,
                revision_id: Some(target),
                actor_id: actor,
                reason_code: reason,
            })
            .map_err(proxy_status)?;
        Ok(Response::new(proto::RollbackProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    pub async fn retire_proxy(
        &self,
        request: Request<proto::RetireProxyRequest>,
    ) -> Result<Response<proto::RetireProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        if self.runtime.is_none() {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        }
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let revision_id = super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?;
        let expected = parse_optional_revision(input.expected_revision_id)?;
        let reason = input
            .reason_code
            .unwrap_or_else(|| "proxy.retire".to_owned());
        self.lifecycle(
            scope.clone(),
            actor.clone(),
            input.request_id.clone(),
            proxy_id.clone(),
            revision_id.clone(),
            expected.clone(),
            reason.clone(),
            super::LifecycleCommand::Retire,
            false,
        )
        .await?;
        let revision = self
            .require_revision(scope.clone(), proxy_id.clone(), revision_id.clone())
            .await?;
        self.reconciled(revision).await?;
        let proxy = self
            .lifecycle(
                scope,
                actor,
                input.request_id,
                proxy_id,
                revision_id,
                expected,
                reason,
                super::LifecycleCommand::Retired,
                false,
            )
            .await?;
        Ok(Response::new(proto::RetireProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    pub async fn list_proxy_activity(
        &self,
        request: Request<proto::ListProxyActivityRequest>,
    ) -> Result<Response<proto::ListProxyActivityResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(input.proxy_id.clone()).map_err(proxy_status)?;
        let store = Arc::clone(&self.store);
        let page_size = usize::try_from(input.page_size).map_err(|_| invalid_status())?;
        let page_token = input.page_token.clone();
        let page = tokio::task::spawn_blocking(move || {
            store.list_activity(ListProxyActivity {
                scope,
                proxy_id,
                page_size,
                page_token,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        Ok(Response::new(proto::ListProxyActivityResponse {
            activity: page.activity.into_iter().map(activity_to_proto).collect(),
            next_page_token: page.next_page_token,
        }))
    }
}
