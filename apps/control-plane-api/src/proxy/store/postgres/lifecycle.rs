use sha2::{Digest, Sha256};

use super::super::shared::{IdempotencyRecord, ensure_scope_match, hash_hex, validate_request_id, validate_scope};
use super::super::{McpProxy, TransitionProxyLifecycle};
use super::idempotency::{insert_idempotency, query_idempotency};
use super::rows::state_to_text;
use super::transitions::insert_lifecycle_transition;
use super::{PostgresProxyStore, load_proxy, query_proxy_for_update, query_revision_row};
use crate::proxy::{LifecycleTransition, ProxyError};

pub(super) fn transition(store: &PostgresProxyStore, input: TransitionProxyLifecycle) -> Result<McpProxy, ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)?;
    let actor = crate::proxy::validation::bounded_required_string(input.actor_id)?;
    let reason = crate::proxy::validation::bounded_required_string(input.reason_code)?;
    let operation = input.command.operation();
    let payload_hash = hash_hex(Sha256::digest(format!("{}:{}:{:?}:{}:{}:{}", input.proxy_id, input.revision_id, input.expected_revision_id, actor, reason, input.approved)).as_slice());
    let mut client = store.client.lock().map_err(|_| super::super::shared::configuration_error())?;
    let mut tx = client.transaction().map_err(|_| super::super::shared::configuration_error())?;
    if let Some(record) = query_idempotency(&mut tx, &input.request_id, operation, &payload_hash, &input.scope)? {
        tx.commit().map_err(|_| super::super::shared::configuration_error())?;
        return load_proxy(&mut *client, &record.proxy_id, None);
    }
    let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?.ok_or_else(ProxyError::proxy_not_found)?;
    ensure_scope_match(&proxy.scope, &input.scope)?;
    if proxy.active_revision_id != input.expected_revision_id || proxy.active_revision_id.as_ref() != Some(&input.revision_id) { return Err(ProxyError::revision_conflict()); }
    let transition = LifecycleTransition::new(proxy.lifecycle_state, input.command, input.approved)?;
    let revision = query_revision_row(&mut tx, &input.proxy_id, &input.revision_id)?.ok_or_else(ProxyError::revision_not_found)?;
    if !revision.published { return Err(ProxyError::immutable_revision()); }
    tx.execute("UPDATE mcp_proxies SET lifecycle_state = $1, desired_state = $1 WHERE proxy_id = $2", &[&state_to_text(transition.next_state), input.proxy_id.as_uuid()]).map_err(|_| super::super::shared::configuration_error())?;
    tx.execute("UPDATE mcp_proxy_revisions SET lifecycle_state = $1 WHERE proxy_id = $2 AND revision_id = $3", &[&state_to_text(transition.next_state), input.proxy_id.as_uuid(), input.revision_id.as_uuid()]).map_err(|_| super::super::shared::configuration_error())?;
    insert_lifecycle_transition(&mut tx, operation, &input.scope, &input.proxy_id, Some(&input.revision_id), Some(transition.prior_state), transition.next_state, Some(&actor), &reason, "committed", validate_request_id(&input.request_id)?)?;
    insert_idempotency(&mut tx, IdempotencyRecord { request_id: input.request_id, operation, payload_hash, proxy_id: input.proxy_id.to_string(), revision_id: None, scope: input.scope })?;
    tx.commit().map_err(|_| super::super::shared::configuration_error())?;
    load_proxy(&mut *client, &input.proxy_id.to_string(), None)
}
