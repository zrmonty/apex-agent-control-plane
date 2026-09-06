use super::super::*;
#[cfg(feature = "postgres")]
use crate::ManagedLifecycleAction as Action;
use crate::{AcceptedManagedLifecycle, ManagedLifecycleInput};

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    #[cfg(feature = "postgres")]
    pub fn with_managed_store(
        mut self,
        store: Arc<super::super::super::PostgresProxyStore>,
    ) -> Self {
        self.managed = Some(store);
        self
    }

    pub(super) async fn accept_managed(
        &self,
        mut input: ManagedLifecycleInput,
    ) -> Result<AcceptedManagedLifecycle, Status> {
        validate_request_id(&input.request_id)?;
        #[cfg(not(feature = "postgres"))]
        {
            let _ = &mut input;
            Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ))
        }
        #[cfg(feature = "postgres")]
        {
            let store = self.managed.as_ref().cloned().ok_or_else(|| {
                Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")
            })?;
            // Handlers authenticate exact scope before reaching this boundary.
            // A committed retry depends on frozen semantics, not today's approval
            // authority or revision lookup. The write path rechecks atomically.
            let retry_store = Arc::clone(&store);
            let retry_input = input.clone();
            if let Some(accepted) = tokio::task::spawn_blocking(move || {
                retry_store.accepted_managed_retry(&retry_input)
            })
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)?
            {
                return Ok(accepted);
            }
            let approval_action = match &input.action {
                Action::Deploy => Some("deploy"),
                Action::Resume => Some("resume"),
                Action::Rotate { .. } => Some("rotate_credentials"),
                Action::Rollback { .. } => Some("rollback"),
                _ => None,
            };
            if let Some(action) = approval_action {
                let revision_id = match &input.action {
                    Action::Rollback { target_revision_id } => target_revision_id.clone(),
                    _ => input.revision_id.clone(),
                };
                let revision = self
                    .require_revision(
                        input.scope.clone(),
                        input.proxy_id.clone(),
                        revision_id.clone(),
                    )
                    .await?;
                input.approved =
                    revision.spec.governance_binding.approval_mode == super::ApprovalMode::None;
                if !input.approved
                    && let Some(authority) = &self.approvals
                {
                    let authority = Arc::clone(authority);
                    let query = super::ProxyApprovalRequest {
                        scope: input.scope.clone(),
                        proxy_id: input.proxy_id.clone(),
                        revision_id,
                        actor_id: input.actor_id.clone(),
                        action: action.into(),
                    };
                    input.approved =
                        tokio::task::spawn_blocking(move || authority.is_approved(query))
                            .await
                            .map_err(internal_status)?
                            .map_err(proxy_status)?;
                }
            }
            tokio::task::spawn_blocking(move || {
                store.accept_managed_lifecycle(&input).inspect_err(|error| {
                    eprintln!("managed_lifecycle_refused code={}", error.code());
                })
            })
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)
        }
    }

    pub async fn get_proxy_operation(
        &self,
        request: Request<proto::GetProxyOperationRequest>,
    ) -> Result<Response<proto::GetProxyOperationResponse>, Status> {
        let resource = request
            .get_ref()
            .scope
            .as_ref()
            .ok_or_else(invalid_status)?;
        let scope = scope(resource.workspace_id.clone(), resource.namespace_id.clone());
        self.authenticate_scope(&request, &scope)?;
        let proxy_id = ProxyId::new(&resource.proxy_id).map_err(proxy_status)?;
        let operation_id = request.into_inner().operation_id;
        validate_request_id(&operation_id)?;
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (scope, proxy_id);
            Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ))
        }
        #[cfg(feature = "postgres")]
        {
            let store = self.managed.as_ref().cloned().ok_or_else(|| {
                Status::failed_precondition("PROXY_RUNTIME_UNAVAILABLE: request rejected safely")
            })?;
            let operation = tokio::task::spawn_blocking(move || {
                store.get_proxy_operation(&scope, &proxy_id, &operation_id)
            })
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)?
            .ok_or_else(|| {
                Status::not_found("PROXY_OPERATION_NOT_FOUND: request rejected safely")
            })?;
            Ok(Response::new(proto::GetProxyOperationResponse {
                operation: Some(operation),
            }))
        }
    }
}
