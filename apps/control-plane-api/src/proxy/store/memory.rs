use std::sync::Mutex;

use super::shared::{
    CREATE_OPERATION, IdempotencyRecord, PUBLISH_OPERATION, RETIRE_OPERATION, StoreProxy,
    StoreState, StoredRevision, UPDATE_DRAFT_OPERATION, build_revision, create_payload_hash,
    ensure_scope_match, list_from_rows, publish_payload_hash, retire_payload_hash, revision_key,
    validate_create, validate_publish, validate_request_id, validate_retire, validate_scope,
    validate_update, update_payload_hash,
};
use super::{
    CreateProxy, ListProxies, ListProxiesPage, McpProxy, ProxyRevisionStore, ProxyStore,
    PublishRevision, RetireProxy, UpdateProxyDraft,
};
use crate::ExactScope;
use crate::proxy::{
    McpProxyRevision, ProxyError, ProxyLifecycleState, ProxyRedactionStatus, ProxyId,
    ProxyRevisionId,
};

#[derive(Debug, Default)]
pub struct InMemoryProxyStore {
    state: Mutex<StoreState>,
}

impl ProxyStore for InMemoryProxyStore {
    fn create(&self, input: CreateProxy) -> Result<McpProxy, ProxyError> {
        let (display_name, description, owner) = validate_create(&input)?;
        let created_at_millis = validate_request_id(&input.request_id)?;
        let payload_hash = create_payload_hash(
            &input,
            &display_name,
            description.as_deref(),
            owner.as_deref(),
        );
        let mut state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(CREATE_OPERATION, &input.request_id, &payload_hash, &input.scope)? {
            return state.replay_proxy(&record);
        }
        state.ensure_identity_available(&input.scope, &input.proxy_id, &input.slug)?;
        let proxy = StoreProxy {
            proxy_id: input.proxy_id,
            scope: input.scope,
            display_name,
            slug: input.slug,
            description,
            owner,
            lifecycle_state: ProxyLifecycleState::Draft,
            redaction_status: ProxyRedactionStatus::Redacted,
            active_revision_id: None,
            draft_revision_id: None,
            created_at_micros: u128::from(created_at_millis) * 1_000,
        };
        let response = proxy.to_proxy(&state.revisions, None);
        state.proxies.insert(response.proxy_id.to_string(), proxy);
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: CREATE_OPERATION,
            payload_hash,
            proxy_id: response.proxy_id.to_string(),
            revision_id: None,
            scope: response.scope.clone(),
        });
        Ok(response)
    }

    fn update_draft(&self, input: UpdateProxyDraft) -> Result<McpProxy, ProxyError> {
        let (actor_id, spec_json) = validate_update(&input)?;
        let created_at_millis = validate_request_id(&input.request_id)?;
        let payload_hash = update_payload_hash(&input, &actor_id, &spec_json);
        let mut state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(
            UPDATE_DRAFT_OPERATION,
            &input.request_id,
            &payload_hash,
            &input.scope,
        )? {
            return state.replay_proxy(&record);
        }
        let key = input.proxy_id.to_string();
        let current = state.proxies.get(&key).ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&current.scope, &input.scope)?;
        if current.draft_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        let revision_id = ProxyRevisionId::new(&input.request_id).expect("validated request id");
        let revision = build_revision(
            input.proxy_id.clone(),
            revision_id.clone(),
            input.spec,
            actor_id,
            ProxyLifecycleState::Draft,
            ProxyRedactionStatus::Redacted,
            created_at_millis,
        )?;
        state.revisions.insert(
            revision_key(&input.proxy_id, &revision_id),
            StoredRevision::draft(revision),
        );
        let proxy = state.proxies.get_mut(&key).ok_or_else(ProxyError::proxy_not_found)?;
        proxy.draft_revision_id = Some(revision_id.clone());
        let response = proxy.clone().to_proxy(&state.revisions, None);
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: UPDATE_DRAFT_OPERATION,
            payload_hash,
            proxy_id: key,
            revision_id: Some(revision_id.to_string()),
            scope: response.scope.clone(),
        });
        Ok(response)
    }

    fn publish_revision(&self, input: PublishRevision) -> Result<McpProxyRevision, ProxyError> {
        let actor_id = validate_publish(&input)?;
        let created_at_millis = validate_request_id(&input.request_id)?;
        let payload_hash = publish_payload_hash(&input, &actor_id);
        let mut state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(PUBLISH_OPERATION, &input.request_id, &payload_hash, &input.scope)? {
            return state.replay_revision(&record);
        }
        let key = input.proxy_id.to_string();
        let proxy = state.proxies.get(&key).ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&proxy.scope, &input.scope)?;
        if proxy.active_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        if proxy.lifecycle_state == ProxyLifecycleState::Retired {
            return Err(ProxyError::identity_conflict());
        }
        let draft = state
            .revisions
            .get(&revision_key(&input.proxy_id, &input.draft_revision_id))
            .cloned()
            .ok_or_else(ProxyError::revision_not_found)?;
        if draft.published {
            return Err(ProxyError::immutable_revision());
        }
        let revision_id = ProxyRevisionId::new(&input.request_id).expect("validated request id");
        let revision = build_revision(
            input.proxy_id.clone(),
            revision_id.clone(),
            draft.revision.spec,
            actor_id,
            ProxyLifecycleState::Draft,
            ProxyRedactionStatus::Redacted,
            created_at_millis,
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
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: PUBLISH_OPERATION,
            payload_hash,
            proxy_id: key,
            revision_id: Some(revision_id.to_string()),
            scope: input.scope,
        });
        Ok(revision)
    }

    fn get(&self, scope: ExactScope, proxy_id: ProxyId) -> Result<McpProxy, ProxyError> {
        validate_scope(&scope)?;
        let state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        let proxy = state.proxies.get(&proxy_id.to_string()).ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&proxy.scope, &scope)?;
        Ok(proxy.to_proxy(&state.revisions, None))
    }

    fn list(&self, query: ListProxies) -> Result<ListProxiesPage, ProxyError> {
        validate_scope(&query.scope)?;
        super::shared::parse_cursor(&query.page_token)?;
        let state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        let rows = state
            .proxies
            .values()
            .filter(|proxy| proxy.scope == query.scope)
            .cloned()
            .collect();
        Ok(list_from_rows(rows, &query))
    }
}

impl ProxyRevisionStore for InMemoryProxyStore {
    fn get_revision(
        &self,
        scope: ExactScope,
        proxy_id: ProxyId,
        revision_id: ProxyRevisionId,
    ) -> Result<McpProxyRevision, ProxyError> {
        validate_scope(&scope)?;
        let state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        let proxy = state.proxies.get(&proxy_id.to_string()).ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&proxy.scope, &scope)?;
        state
            .revisions
            .get(&revision_key(&proxy_id, &revision_id))
            .map(|stored| stored.revision.clone())
            .ok_or_else(ProxyError::revision_not_found)
    }

    fn retire(&self, input: RetireProxy) -> Result<McpProxy, ProxyError> {
        validate_retire(&input)?;
        let payload_hash = retire_payload_hash(&input);
        let mut state = self.state.lock().map_err(|_| super::shared::configuration_error())?;
        if let Some(record) = state.check_idempotency(RETIRE_OPERATION, &input.request_id, &payload_hash, &input.scope)? {
            return state.replay_proxy(&record);
        }
        let key = input.proxy_id.to_string();
        let proxy = state.proxies.get_mut(&key).ok_or_else(ProxyError::proxy_not_found)?;
        ensure_scope_match(&proxy.scope, &input.scope)?;
        if proxy.active_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        proxy.lifecycle_state = ProxyLifecycleState::Retired;
        let response = proxy.clone().to_proxy(&state.revisions, None);
        state.record_idempotency(IdempotencyRecord {
            request_id: input.request_id,
            operation: RETIRE_OPERATION,
            payload_hash,
            proxy_id: key,
            revision_id: None,
            scope: input.scope,
        });
        Ok(response)
    }
}
