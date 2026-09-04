use super::super::*;

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    pub(super) async fn lifecycle(
        &self,
        scope: ExactScope,
        actor_id: String,
        request_id: String,
        proxy_id: ProxyId,
        revision_id: super::ProxyRevisionId,
        expected_revision_id: Option<super::ProxyRevisionId>,
        reason_code: String,
        command: super::LifecycleCommand,
        approved: bool,
    ) -> Result<McpProxy, Status> {
        let Some(events) = &self.events else {
            return Err(proxy_status(ProxyError::event_sink_unavailable()));
        };
        let event = ProxyLifecycleEvent {
            request_id: request_id.clone(),
            operation: command.operation().to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id.clone(),
            revision_id: Some(revision_id.clone()),
            actor_id: actor_id.clone(),
            reason_code: reason_code.clone(),
        };
        let store = Arc::clone(&self.store);
        let proxy = tokio::task::spawn_blocking(move || {
            store.transition(TransitionProxyLifecycle {
                request_id,
                scope,
                proxy_id,
                revision_id,
                expected_revision_id,
                actor_id,
                reason_code,
                command,
                approved,
            })
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        events.emit(event).map_err(proxy_status)?;
        Ok(proxy)
    }

    pub(super) async fn reconciled(&self, revision: McpProxyRevision) -> Result<(), Status> {
        let Some(runtime) = &self.runtime else {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        };
        let runtime = Arc::clone(runtime);
        tokio::task::spawn_blocking(move || runtime.reconcile(&revision))
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)
    }

    async fn reconcile_to_ready(
        &self,
        scope: ExactScope,
        actor_id: String,
        proxy: McpProxy,
        revision_id: super::ProxyRevisionId,
    ) -> Result<McpProxy, Status> {
        if proxy.lifecycle_state != super::ProxyLifecycleState::Provisioning {
            return Ok(proxy);
        }
        let revision = self
            .require_revision(scope.clone(), proxy.proxy_id.clone(), revision_id.clone())
            .await?;
        if let Err(error) = self.reconciled(revision).await {
            let _ = self
                .lifecycle(
                    scope.clone(),
                    actor_id.clone(),
                    uuid::Uuid::now_v7().hyphenated().to_string(),
                    proxy.proxy_id.clone(),
                    revision_id.clone(),
                    Some(revision_id.clone()),
                    "proxy.runtime_failed".to_owned(),
                    super::LifecycleCommand::Fail,
                    false,
                )
                .await;
            return Err(error);
        }
        self.lifecycle(
            scope,
            actor_id,
            uuid::Uuid::now_v7().hyphenated().to_string(),
            proxy.proxy_id,
            revision_id.clone(),
            Some(revision_id),
            "proxy.ready".to_owned(),
            super::LifecycleCommand::Ready,
            false,
        )
        .await
    }

    pub async fn validate_proxy(
        &self,
        request: Request<proto::ValidateProxyRequest>,
    ) -> Result<Response<proto::ValidateProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor_id = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let revision_id =
            parse_optional_revision(input.expected_revision_id)?.ok_or_else(invalid_status)?;
        let stored = self
            .require_revision(scope.clone(), proxy_id.clone(), revision_id.clone())
            .await?;
        let spec: super::ProxySpec = input
            .draft
            .ok_or_else(invalid_status)?
            .try_into()
            .map_err(proxy_status)?;
        if spec != stored.spec {
            return Err(Status::aborted(
                "PROXY_REVISION_CONFLICT: request rejected safely",
            ));
        }
        super::validate_proxy_spec(&stored.spec).map_err(proxy_status)?;
        self.lifecycle(
            scope.clone(),
            actor_id.clone(),
            input.request_id.clone(),
            proxy_id.clone(),
            revision_id.clone(),
            Some(revision_id.clone()),
            "proxy.validation_started".to_owned(),
            super::LifecycleCommand::Validate,
            false,
        )
        .await?;
        self.lifecycle(
            scope,
            actor_id,
            input.request_id,
            proxy_id,
            revision_id.clone(),
            Some(revision_id),
            "proxy.validation_succeeded".to_owned(),
            super::LifecycleCommand::ValidationSucceeded,
            false,
        )
        .await?;
        Ok(Response::new(proto::ValidateProxyResponse {
            report: Some(proto::ProxyValidationReport {
                valid: true,
                error_messages: vec![],
                warning_messages: vec![],
                validation_id: "validated".to_owned(),
                redaction_status: proto::McpProxyRedactionStatus::Redacted as i32,
            }),
        }))
    }

    pub async fn deploy_proxy(
        &self,
        request: Request<proto::DeployProxyRequest>,
    ) -> Result<Response<proto::DeployProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        let proxy_id = ProxyId::new(input.proxy_id).map_err(proxy_status)?;
        let revision_id = super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?;
        let expected = parse_optional_revision(input.expected_revision_id)?;
        let store = Arc::clone(&self.store);
        let revision_scope = scope.clone();
        let revision_proxy = proxy_id.clone();
        let revision_copy = revision_id.clone();
        let revision = tokio::task::spawn_blocking(move || {
            store.get_revision(revision_scope, revision_proxy, revision_copy)
        })
        .await
        .map_err(internal_status)?
        .map_err(proxy_status)?;
        let approved = match revision.spec.governance_binding.approval_mode {
            super::ApprovalMode::None => true,
            _ => {
                let Some(authority) = &self.approvals else {
                    return Err(Status::failed_precondition(
                        "PROXY_APPROVAL_REQUIRED: request rejected safely",
                    ));
                };
                authority
                    .is_approved(super::ProxyApprovalRequest {
                        scope: scope.clone(),
                        proxy_id: proxy_id.clone(),
                        revision_id: revision_id.clone(),
                        actor_id: actor.clone(),
                        action: "deploy".to_owned(),
                    })
                    .map_err(proxy_status)?
            }
        };
        if !approved {
            return Err(Status::failed_precondition(
                "PROXY_APPROVAL_REQUIRED: request rejected safely",
            ));
        }
        if self.runtime.is_none() {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        }
        let proxy = self
            .lifecycle(
                scope.clone(),
                actor.clone(),
                input.request_id,
                proxy_id.clone(),
                revision_id.clone(),
                expected,
                "proxy.deploy".to_owned(),
                super::LifecycleCommand::Deploy,
                approved,
            )
            .await?;
        let proxy = self
            .reconcile_to_ready(scope, actor, proxy, revision_id)
            .await?;
        Ok(Response::new(proto::DeployProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    pub async fn pause_proxy(
        &self,
        request: Request<proto::PauseProxyRequest>,
    ) -> Result<Response<proto::PauseProxyResponse>, Status> {
        self.pause_or_resume(request, super::LifecycleCommand::Pause)
            .await
    }
    pub async fn resume_proxy(
        &self,
        request: Request<proto::ResumeProxyRequest>,
    ) -> Result<Response<proto::ResumeProxyResponse>, Status> {
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
        let proxy = self
            .lifecycle(
                scope.clone(),
                actor.clone(),
                input.request_id,
                proxy_id,
                revision_id.clone(),
                parse_optional_revision(input.expected_revision_id)?,
                "proxy.resume".to_owned(),
                super::LifecycleCommand::Resume,
                false,
            )
            .await?;
        let proxy = self
            .reconcile_to_ready(scope, actor, proxy, revision_id)
            .await?;
        Ok(Response::new(proto::ResumeProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    async fn pause_or_resume(
        &self,
        request: Request<proto::PauseProxyRequest>,
        command: super::LifecycleCommand,
    ) -> Result<Response<proto::PauseProxyResponse>, Status> {
        let input = request.get_ref();
        let scope = scope(input.workspace_id.clone(), input.namespace_id.clone());
        let actor = self.authenticate_scope(&request, &scope)?;
        let input = request.into_inner();
        if self.runtime.is_none() {
            return Err(Status::failed_precondition(
                "PROXY_RUNTIME_UNAVAILABLE: request rejected safely",
            ));
        }
        let reason = input
            .reason_code
            .unwrap_or_else(|| "proxy.pause".to_owned());
        let proxy = self
            .lifecycle(
                scope,
                actor,
                input.request_id,
                ProxyId::new(input.proxy_id).map_err(proxy_status)?,
                super::ProxyRevisionId::new(input.revision_id).map_err(proxy_status)?,
                parse_optional_revision(input.expected_revision_id)?,
                reason,
                command,
                false,
            )
            .await?;
        Ok(Response::new(proto::PauseProxyResponse {
            proxy: Some(proxy_to_proto(proxy)),
        }))
    }

    pub(super) async fn require_revision(
        &self,
        scope: ExactScope,
        proxy_id: ProxyId,
        revision_id: super::ProxyRevisionId,
    ) -> Result<super::McpProxyRevision, Status> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.get_revision(scope, proxy_id, revision_id))
            .await
            .map_err(internal_status)?
            .map_err(proxy_status)
    }
}
