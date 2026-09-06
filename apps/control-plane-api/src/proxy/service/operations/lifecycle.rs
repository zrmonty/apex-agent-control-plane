use super::super::*;

impl<R: OperatorCredentialResolver> McpProxyService<R> {
    // This operation mirrors the complete lifecycle RPC boundary and its audit fields.
    #[allow(clippy::too_many_arguments)]
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
        self.require_event_sink()?;
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
        self.emit_event(event).await?;
        Ok(proxy)
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
        validate_request_id(&input.request_id)?;
        #[cfg(feature = "postgres")]
        if let Some(store) = &self.managed {
            let (store, scope, proxy_id) = (Arc::clone(store), scope.clone(), proxy_id.clone());
            if tokio::task::spawn_blocking(move || store.is_managed(&scope, &proxy_id))
                .await
                .map_err(internal_status)?
                .map_err(proxy_status)?
            {
                // Validation is a read-only report once desired authority is
                // journal-managed, including validation of a newly edited draft.
                return Ok(validated_response());
            }
        }
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
        Ok(validated_response())
    }

    pub async fn deploy_proxy(
        &self,
        request: Request<proto::DeployProxyRequest>,
    ) -> Result<Response<proto::DeployProxyResponse>, Status> {
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
                reason_code: "proxy.deploy".to_owned(),
                action: super::super::super::ManagedLifecycleAction::Deploy,
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::DeployProxyResponse {
            proxy: Some(accepted.proxy),
            operation: Some(accepted.operation),
        }))
    }

    pub async fn pause_proxy(
        &self,
        request: Request<proto::PauseProxyRequest>,
    ) -> Result<Response<proto::PauseProxyResponse>, Status> {
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
                    .unwrap_or_else(|| "proxy.pause".to_owned()),
                action: super::super::super::ManagedLifecycleAction::Pause,
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::PauseProxyResponse {
            proxy: Some(accepted.proxy),
            operation: Some(accepted.operation),
        }))
    }

    pub async fn resume_proxy(
        &self,
        request: Request<proto::ResumeProxyRequest>,
    ) -> Result<Response<proto::ResumeProxyResponse>, Status> {
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
                reason_code: "proxy.resume".to_owned(),
                action: super::super::super::ManagedLifecycleAction::Resume,
                approved: false,
            })
            .await?;
        Ok(Response::new(proto::ResumeProxyResponse {
            proxy: Some(accepted.proxy),
            operation: Some(accepted.operation),
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

fn validated_response() -> Response<proto::ValidateProxyResponse> {
    Response::new(proto::ValidateProxyResponse {
        report: Some(proto::ProxyValidationReport {
            valid: true,
            error_messages: vec![],
            warning_messages: vec![],
            validation_id: "validated".into(),
            redaction_status: proto::McpProxyRedactionStatus::Redacted as i32,
        }),
    })
}
