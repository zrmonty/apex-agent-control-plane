use super::super::shared::{
    IdempotencyRecord, ROLLBACK_OPERATION, ROTATE_OPERATION, StoredRevision, build_revision,
    ensure_scope_match, format_rfc3339_micros, lifecycle_payload_hash, revision_key,
    rollback_payload_hash, rotate_payload_hash, validate_reason_code, validate_request_id,
    validate_scope,
};
use super::super::transitions::LifecycleTransition;
use super::super::{
    ListProxyActivity, ListProxyActivityPage, McpProxy, McpProxyRevision, ProxyActivity,
    ProxyLifecycleStore, RollbackProxy, RotateProxyCredentials, TransitionProxyLifecycle,
};
use super::InMemoryProxyStore;
use crate::proxy::{ProxyError, ProxyLifecycleState, ProxyRedactionStatus, ProxyRevisionId};

impl ProxyLifecycleStore for InMemoryProxyStore {
    fn transition(&self, input: TransitionProxyLifecycle) -> Result<McpProxy, ProxyError> {
        super::super::shared::validate_request_id(&input.request_id)?;
        super::super::shared::validate_scope(&input.scope)?;
        let actor_id =
            super::super::super::validation::bounded_required_string(input.actor_id.clone())?;
        let reason_code = validate_reason_code(input.reason_code.clone())?;
        let operation = input.command.operation();
        let payload_hash = lifecycle_payload_hash(&input, &actor_id, &reason_code);
        let mut state = self
            .state
            .lock()
            .map_err(|_| super::super::shared::configuration_error())?;
        if let Some(record) =
            state.check_idempotency(operation, &input.request_id, &payload_hash, &input.scope)?
        {
            return state.replay_proxy(&record);
        }
        let key = input.proxy_id.to_string();
        let current = state
            .proxies
            .get(&key)
            .ok_or_else(ProxyError::proxy_not_found)?;
        super::super::shared::ensure_scope_match(&current.scope, &input.scope)?;
        if current.active_revision_id != input.expected_revision_id
            || current.active_revision_id.as_ref() != Some(&input.revision_id)
        {
            return Err(ProxyError::revision_conflict());
        }
        let transition = super::super::super::lifecycle::LifecycleTransition::new(
            current.lifecycle_state,
            input.command,
            input.approved,
        )?;
        let revision = state
            .revisions
            .get_mut(&super::super::shared::revision_key(
                &input.proxy_id,
                &input.revision_id,
            ))
            .ok_or_else(ProxyError::revision_not_found)?;
        if !revision.published {
            return Err(ProxyError::immutable_revision());
        }
        revision.revision.lifecycle_state = transition.next_state;
        let proxy = state
            .proxies
            .get_mut(&key)
            .ok_or_else(ProxyError::proxy_not_found)?;
        proxy.lifecycle_state = transition.next_state;
        let response = proxy.clone().to_proxy(&state.revisions, None);
        state.record_transition(
            super::super::transitions::LifecycleTransition::new(
                operation,
                input.scope.clone(),
                input.proxy_id.clone(),
                Some(input.revision_id.clone()),
                Some(transition.prior_state),
                transition.next_state,
                Some(actor_id),
                reason_code,
                "committed",
            )
            .with_identity(
                input.request_id.clone(),
                super::super::shared::validate_request_id(&input.request_id)?,
            ),
        );
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation,
            payload_hash,
            proxy_id: key,
            revision_id: None,
            scope: input.scope,
        });
        Ok(response)
    }

    fn rotate_credentials(
        &self,
        input: RotateProxyCredentials,
    ) -> Result<McpProxyRevision, ProxyError> {
        let occurred_at_micros = validate_request_id(&input.request_id)?;
        if input.secret_refs.is_empty()
            || input.secret_refs.len() > super::super::super::MAX_SECRET_REFS
        {
            return Err(ProxyError::invalid_proxy_spec(
                "Credential rotation requires a bounded non-empty secret reference set.",
            ));
        }
        let actor_id =
            super::super::super::validation::bounded_required_string(input.actor_id.clone())?;
        let reason_code = validate_reason_code(input.reason_code.clone())?;
        let payload_hash = rotate_payload_hash(&input, &actor_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| super::super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(
            ROTATE_OPERATION,
            &input.request_id,
            &payload_hash,
            &input.scope,
        )? {
            return state.replay_revision(&record);
        }
        let key = input.proxy_id.to_string();
        let current = state
            .proxies
            .get(&key)
            .ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&current.scope, &input.scope)?;
        if current.lifecycle_state == ProxyLifecycleState::Retired
            || current.active_revision_id != input.expected_revision_id
            || current.active_revision_id.as_ref() != Some(&input.revision_id)
        {
            return Err(ProxyError::revision_conflict());
        }
        let source = state
            .revisions
            .get(&revision_key(&input.proxy_id, &input.revision_id))
            .cloned()
            .ok_or_else(ProxyError::revision_not_found)?;
        if !source.published {
            return Err(ProxyError::immutable_revision());
        }
        let mut spec = source.revision.spec.clone();
        for upstream in &mut spec.upstreams {
            upstream.secret_refs = input.secret_refs.clone();
            upstream.credential_ref = input.secret_refs.first().cloned();
        }
        for profile in &mut spec.cli_profiles {
            profile.secret_refs = input.secret_refs.clone();
        }
        super::super::super::validate_proxy_spec(&spec)?;
        let revision_id = ProxyRevisionId::new(&input.request_id).expect("validated request id");
        let revision = build_revision(
            input.proxy_id.clone(),
            revision_id.clone(),
            spec,
            actor_id.clone(),
            source.revision.lifecycle_state,
            ProxyRedactionStatus::Redacted,
            occurred_at_micros,
        )?;
        state.revisions.insert(
            revision_key(&input.proxy_id, &revision_id),
            StoredRevision::published(revision.clone()),
        );
        state
            .proxies
            .get_mut(&key)
            .ok_or_else(ProxyError::proxy_not_found)?
            .active_revision_id = Some(revision_id.clone());
        state.record_transition(
            LifecycleTransition::new(
                ROTATE_OPERATION,
                input.scope.clone(),
                input.proxy_id.clone(),
                Some(revision_id.clone()),
                Some(source.revision.lifecycle_state),
                source.revision.lifecycle_state,
                Some(actor_id),
                reason_code,
                "committed",
            )
            .with_identity(input.request_id.clone(), occurred_at_micros),
        );
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: super::super::shared::ROTATE_OPERATION,
            payload_hash,
            proxy_id: key,
            revision_id: Some(revision_id.to_string()),
            scope: input.scope,
        });
        Ok(revision)
    }

    fn rollback(&self, input: RollbackProxy) -> Result<McpProxy, ProxyError> {
        let occurred_at_micros = validate_request_id(&input.request_id)?;
        let actor_id =
            super::super::super::validation::bounded_required_string(input.actor_id.clone())?;
        let reason_code = validate_reason_code(input.reason_code.clone())?;
        let payload_hash = rollback_payload_hash(&input, &actor_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| super::super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(
            ROLLBACK_OPERATION,
            &input.request_id,
            &payload_hash,
            &input.scope,
        )? {
            return state.replay_proxy(&record);
        }
        let key = input.proxy_id.to_string();
        let current = state
            .proxies
            .get(&key)
            .ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&current.scope, &input.scope)?;
        if current.active_revision_id != input.expected_revision_id
            || current.active_revision_id.as_ref() != Some(&input.revision_id)
        {
            return Err(ProxyError::revision_conflict());
        }
        let target = state
            .revisions
            .get(&revision_key(&input.proxy_id, &input.target_revision_id))
            .cloned()
            .ok_or_else(ProxyError::revision_not_found)?;
        if !target.published || target.revision.lifecycle_state != ProxyLifecycleState::Ready {
            return Err(ProxyError::invalid_lifecycle_transition());
        }
        let prior_state = current.lifecycle_state;
        let proxy = state
            .proxies
            .get_mut(&key)
            .ok_or_else(ProxyError::proxy_not_found)?;
        proxy.active_revision_id = Some(input.target_revision_id.clone());
        proxy.lifecycle_state = ProxyLifecycleState::Ready;
        let response = proxy.clone().to_proxy(&state.revisions, None);
        state.record_transition(
            LifecycleTransition::new(
                ROLLBACK_OPERATION,
                input.scope.clone(),
                input.proxy_id.clone(),
                Some(input.target_revision_id.clone()),
                Some(prior_state),
                ProxyLifecycleState::Ready,
                Some(actor_id),
                reason_code,
                "committed",
            )
            .with_identity(input.request_id.clone(), occurred_at_micros),
        );
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: super::super::shared::ROLLBACK_OPERATION,
            payload_hash,
            proxy_id: key,
            revision_id: Some(input.target_revision_id.to_string()),
            scope: input.scope,
        });
        Ok(response)
    }

    fn list_activity(&self, query: ListProxyActivity) -> Result<ListProxyActivityPage, ProxyError> {
        validate_scope(&query.scope)?;
        let start = if query.page_token.is_empty() {
            0
        } else {
            query
                .page_token
                .parse::<usize>()
                .map_err(|_| ProxyError::invalid_cursor())?
        };
        let state = self
            .state
            .lock()
            .map_err(|_| super::super::shared::configuration_error())?;
        let proxy = state
            .proxies
            .get(&query.proxy_id.to_string())
            .ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&proxy.scope, &query.scope)?;
        let entries: Vec<_> = state
            .transitions
            .iter()
            .filter(|entry| entry.proxy_id == query.proxy_id && entry.scope == query.scope)
            .cloned()
            .collect();
        let page_size = query.page_size.max(1);
        let page = entries
            .iter()
            .skip(start)
            .take(page_size)
            .enumerate()
            .map(|(offset, entry)| {
                let index = start + offset;
                ProxyActivity {
                    activity_id: if entry.transition_id.is_empty() {
                        format!("legacy-{index}")
                    } else {
                        entry.transition_id.clone()
                    },
                    request_id: entry.request_id.clone(),
                    scope: entry.scope.clone(),
                    proxy_id: entry.proxy_id.clone(),
                    revision_id: entry.revision_id.clone(),
                    occurred_at: if entry.occurred_at_micros == 0 {
                        String::new()
                    } else {
                        format_rfc3339_micros(entry.occurred_at_micros)
                    },
                    actor_id: entry.actor_id.clone(),
                    operation: entry.operation.clone(),
                    prior_state: entry.prior_state,
                    next_state: entry.next_state,
                    reason_code: entry.reason_code.clone(),
                    status: entry.status.clone(),
                }
            })
            .collect::<Vec<_>>();
        let next_page_token = if start + page.len() < entries.len() {
            (start + page.len()).to_string()
        } else {
            String::new()
        };
        Ok(ListProxyActivityPage {
            activity: page,
            next_page_token,
        })
    }
}
