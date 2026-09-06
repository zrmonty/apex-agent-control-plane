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
        let input = request.into_inner();
        let accepted = self
            .accept_managed(super::super::super::ManagedLifecycleInput {
                scope,
                actor_id: actor,
                request_id: input.request_id,
                proxy_id: ProxyId::new(input.proxy_id).map_err(proxy_status)?,
                revision_id: super::ProxyRevisionId::new(input.revision_id)
                    .map_err(proxy_status)?,
                expected_revision_id: parse_optional_revision(input.expected_revision_id)?,
                reason_code: input
                    .reason_code
                    .unwrap_or_else(|| "proxy.rotate_credentials".to_owned()),
                action: super::super::super::ManagedLifecycleAction::Rotate {
                    secret_refs: input
                        .secret_refs
                        .into_iter()
                        .map(super::SecretRef::new)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(proxy_status)?,
                },
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::RotateProxyCredentialsResponse {
            revision: Some(accepted.revision),
            operation: Some(accepted.operation),
        }))
    }

    pub async fn rollback_proxy(
        &self,
        request: Request<proto::RollbackProxyRequest>,
    ) -> Result<Response<proto::RollbackProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let accepted = self
            .accept_managed(super::super::super::ManagedLifecycleInput {
                scope,
                actor_id: actor,
                request_id: input.request_id,
                proxy_id: ProxyId::new(input.proxy_id).map_err(proxy_status)?,
                revision_id: super::ProxyRevisionId::new(input.revision_id)
                    .map_err(proxy_status)?,
                expected_revision_id: parse_optional_revision(input.expected_revision_id)?,
                reason_code: input
                    .reason_code
                    .unwrap_or_else(|| "proxy.rollback".to_owned()),
                action: super::super::super::ManagedLifecycleAction::Rollback {
                    target_revision_id: super::ProxyRevisionId::new(input.target_revision_id)
                        .map_err(proxy_status)?,
                },
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::RollbackProxyResponse {
            proxy: Some(accepted.proxy),
            operation: Some(accepted.operation),
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
        let accepted = self
            .accept_managed(super::super::super::ManagedLifecycleInput {
                scope,
                actor_id: actor,
                request_id: input.request_id,
                proxy_id: ProxyId::new(input.proxy_id).map_err(proxy_status)?,
                revision_id: super::ProxyRevisionId::new(input.revision_id)
                    .map_err(proxy_status)?,
                expected_revision_id: parse_optional_revision(input.expected_revision_id)?,
                reason_code: input
                    .reason_code
                    .unwrap_or_else(|| "proxy.retire".to_owned()),
                action: super::super::super::ManagedLifecycleAction::Retire,
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::RetireProxyResponse {
            proxy: Some(accepted.proxy),
            operation: Some(accepted.operation),
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
