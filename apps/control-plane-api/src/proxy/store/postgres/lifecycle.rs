use apex_durability::PostgresClientOps;

use super::super::shared::{
    IdempotencyRecord, ensure_scope_match, lifecycle_payload_hash, list_activity_cursor,
    parse_activity_cursor, rollback_payload_hash, rotate_payload_hash, spec_json,
    validate_reason_code, validate_request_id, validate_scope,
};
use super::super::{
    ListProxyActivity, ListProxyActivityPage, McpProxy, McpProxyRevision, ProxyActivity,
    RollbackProxy, RotateProxyCredentials, TransitionProxyLifecycle,
};
use super::idempotency::{insert_idempotency, query_idempotency};
use super::rows::state_to_text;
use super::transitions::insert_lifecycle_transition;
use super::{
    PostgresProxyStore, load_proxy, load_revision, query_proxy_for_update, query_revision_row,
};
use crate::proxy::{LifecycleTransition, ProxyError};

pub(super) fn transition(
    store: &PostgresProxyStore,
    input: TransitionProxyLifecycle,
) -> Result<McpProxy, ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)?;
    let actor = crate::proxy::validation::bounded_required_string(input.actor_id.clone())?;
    let reason = validate_reason_code(input.reason_code.clone())?;
    let operation = input.command.operation();
    let payload_hash = lifecycle_payload_hash(&input, &actor, &reason);
    let mut client = store
        .client
        .lock()
        .map_err(|_| super::super::shared::configuration_error())?;
    let mut tx = client
        .transaction()
        .map_err(|_| super::super::shared::configuration_error())?;
    let locked_proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
        .ok_or_else(ProxyError::proxy_not_found)?;
    if let Some(record) = query_idempotency(
        &mut tx,
        &input.request_id,
        operation,
        &payload_hash,
        &input.scope,
    )? {
        tx.commit()
            .map_err(|_| super::super::shared::configuration_error())?;
        return load_proxy(&mut *client, &record.proxy_id, None);
    }
    let proxy = locked_proxy;
    ensure_scope_match(&proxy.scope, &input.scope)?;
    if proxy.active_revision_id != input.expected_revision_id
        || proxy.active_revision_id.as_ref() != Some(&input.revision_id)
    {
        return Err(ProxyError::revision_conflict());
    }
    let transition =
        LifecycleTransition::new(proxy.lifecycle_state, input.command, input.approved)?;
    let revision = query_revision_row(&mut tx, &input.proxy_id, &input.revision_id)?
        .ok_or_else(ProxyError::revision_not_found)?;
    if !revision.published {
        return Err(ProxyError::immutable_revision());
    }
    tx.execute(
        "UPDATE mcp_proxies SET lifecycle_state = $1, desired_state = $1 WHERE proxy_id = $2",
        &[
            &state_to_text(transition.next_state),
            input.proxy_id.as_uuid(),
        ],
    )
    .map_err(|_| super::super::shared::configuration_error())?;
    tx.execute("UPDATE mcp_proxy_revisions SET lifecycle_state = $1 WHERE proxy_id = $2 AND revision_id = $3", &[&state_to_text(transition.next_state), input.proxy_id.as_uuid(), input.revision_id.as_uuid()]).map_err(|_| super::super::shared::configuration_error())?;
    insert_lifecycle_transition(
        &mut tx,
        operation,
        &input.scope,
        &input.proxy_id,
        Some(&input.revision_id),
        Some(transition.prior_state),
        transition.next_state,
        Some(&actor),
        &reason,
        "committed",
        validate_request_id(&input.request_id)?,
        Some(input.request_id.as_str()),
    )?;
    insert_idempotency(
        &mut tx,
        IdempotencyRecord {
            request_id: input.request_id,
            operation,
            payload_hash,
            proxy_id: input.proxy_id.to_string(),
            revision_id: None,
            scope: input.scope,
        },
    )?;
    tx.commit()
        .map_err(|_| super::super::shared::configuration_error())?;
    load_proxy(&mut *client, &input.proxy_id.to_string(), None)
}

pub(super) fn rotate_credentials(
    store: &PostgresProxyStore,
    input: RotateProxyCredentials,
) -> Result<McpProxyRevision, ProxyError> {
    let occurred_at_micros = validate_request_id(&input.request_id)?;
    if input.secret_refs.is_empty() || input.secret_refs.len() > crate::proxy::MAX_SECRET_REFS {
        return Err(ProxyError::invalid_proxy_spec(
            "Credential rotation requires a bounded non-empty secret reference set.",
        ));
    }
    let actor = crate::proxy::validation::bounded_required_string(input.actor_id.clone())?;
    let reason = validate_reason_code(input.reason_code.clone())?;
    let payload_hash = rotate_payload_hash(&input, &actor);
    let mut client = store
        .client
        .lock()
        .map_err(|_| super::super::shared::configuration_error())?;
    let mut tx = client
        .transaction()
        .map_err(|_| super::super::shared::configuration_error())?;
    let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
        .ok_or_else(ProxyError::proxy_not_found)?;
    if let Some(record) = query_idempotency(
        &mut tx,
        &input.request_id,
        super::super::shared::ROTATE_OPERATION,
        &payload_hash,
        &input.scope,
    )? {
        tx.commit()
            .map_err(|_| super::super::shared::configuration_error())?;
        return load_revision(
            &mut *client,
            &record.proxy_id,
            record
                .revision_id
                .as_deref()
                .ok_or_else(super::super::shared::configuration_error)?,
        );
    }
    ensure_scope_match(&proxy.scope, &input.scope)?;
    if proxy.lifecycle_state == super::super::ProxyLifecycleState::Retired
        || proxy.active_revision_id != input.expected_revision_id
        || proxy.active_revision_id.as_ref() != Some(&input.revision_id)
    {
        return Err(ProxyError::revision_conflict());
    }
    let source = query_revision_row(&mut tx, &input.proxy_id, &input.revision_id)?
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
    crate::proxy::validate_proxy_spec(&spec)?;
    let revision_id =
        super::super::ProxyRevisionId::new(&input.request_id).expect("validated request id");
    let revision = super::super::shared::build_revision(
        input.proxy_id.clone(),
        revision_id.clone(),
        spec,
        actor.clone(),
        source.revision.lifecycle_state,
        super::super::ProxyRedactionStatus::Redacted,
        occurred_at_micros,
    )?;
    tx.execute(
        "INSERT INTO mcp_proxy_revisions
         (proxy_id, revision_id, spec_json, config_hash, lifecycle_state, redaction_status,
          created_by, created_at_micros, created_at, is_published)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)",
        &[
            input.proxy_id.as_uuid(),
            revision_id.as_uuid(),
            &spec_json(&revision.spec),
            &revision.config_hash,
            &state_to_text(revision.lifecycle_state),
            &super::rows::redaction_to_text(revision.redaction_status),
            &revision.created_by,
            &i64::try_from(occurred_at_micros)
                .map_err(|_| super::super::shared::configuration_error())?,
            &revision.created_at,
        ],
    )
    .map_err(|_| super::super::shared::configuration_error())?;
    tx.execute(
        "UPDATE mcp_proxies SET active_revision_id = $1 WHERE proxy_id = $2",
        &[revision_id.as_uuid(), input.proxy_id.as_uuid()],
    )
    .map_err(|_| super::super::shared::configuration_error())?;
    insert_lifecycle_transition(
        &mut tx,
        super::super::shared::ROTATE_OPERATION,
        &input.scope,
        &input.proxy_id,
        Some(&revision_id),
        Some(source.revision.lifecycle_state),
        source.revision.lifecycle_state,
        Some(&actor),
        &reason,
        "committed",
        occurred_at_micros,
        Some(input.request_id.as_str()),
    )?;
    insert_idempotency(
        &mut tx,
        IdempotencyRecord {
            request_id: input.request_id,
            operation: super::super::shared::ROTATE_OPERATION,
            payload_hash,
            proxy_id: input.proxy_id.to_string(),
            revision_id: Some(revision_id.to_string()),
            scope: input.scope,
        },
    )?;
    tx.commit()
        .map_err(|_| super::super::shared::configuration_error())?;
    load_revision(
        &mut *client,
        &input.proxy_id.to_string(),
        &revision_id.to_string(),
    )
}

pub(super) fn rollback(
    store: &PostgresProxyStore,
    input: RollbackProxy,
) -> Result<McpProxy, ProxyError> {
    let occurred_at_micros = validate_request_id(&input.request_id)?;
    let actor = crate::proxy::validation::bounded_required_string(input.actor_id.clone())?;
    let reason = validate_reason_code(input.reason_code.clone())?;
    let payload_hash = rollback_payload_hash(&input, &actor);
    let mut client = store
        .client
        .lock()
        .map_err(|_| super::super::shared::configuration_error())?;
    let mut tx = client
        .transaction()
        .map_err(|_| super::super::shared::configuration_error())?;
    let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
        .ok_or_else(ProxyError::proxy_not_found)?;
    if let Some(record) = query_idempotency(
        &mut tx,
        &input.request_id,
        super::super::shared::ROLLBACK_OPERATION,
        &payload_hash,
        &input.scope,
    )? {
        tx.commit()
            .map_err(|_| super::super::shared::configuration_error())?;
        return load_proxy(&mut *client, &record.proxy_id, None);
    }
    ensure_scope_match(&proxy.scope, &input.scope)?;
    if proxy.active_revision_id != input.expected_revision_id
        || proxy.active_revision_id.as_ref() != Some(&input.revision_id)
    {
        return Err(ProxyError::revision_conflict());
    }
    let target = query_revision_row(&mut tx, &input.proxy_id, &input.target_revision_id)?
        .ok_or_else(ProxyError::revision_not_found)?;
    if !target.published
        || target.revision.lifecycle_state != super::super::ProxyLifecycleState::Ready
    {
        return Err(ProxyError::invalid_lifecycle_transition());
    }
    let prior_state = proxy.lifecycle_state;
    tx.execute("UPDATE mcp_proxies SET active_revision_id = $1, lifecycle_state = 'ready', desired_state = 'ready' WHERE proxy_id = $2", &[input.target_revision_id.as_uuid(), input.proxy_id.as_uuid()]).map_err(|_| super::super::shared::configuration_error())?;
    insert_lifecycle_transition(
        &mut tx,
        super::super::shared::ROLLBACK_OPERATION,
        &input.scope,
        &input.proxy_id,
        Some(&input.target_revision_id),
        Some(prior_state),
        super::super::ProxyLifecycleState::Ready,
        Some(&actor),
        &reason,
        "committed",
        occurred_at_micros,
        Some(input.request_id.as_str()),
    )?;
    insert_idempotency(
        &mut tx,
        IdempotencyRecord {
            request_id: input.request_id,
            operation: super::super::shared::ROLLBACK_OPERATION,
            payload_hash,
            proxy_id: input.proxy_id.to_string(),
            revision_id: Some(input.target_revision_id.to_string()),
            scope: input.scope,
        },
    )?;
    tx.commit()
        .map_err(|_| super::super::shared::configuration_error())?;
    load_proxy(&mut *client, &input.proxy_id.to_string(), None)
}

pub(super) fn list_activity(
    store: &PostgresProxyStore,
    query: ListProxyActivity,
) -> Result<ListProxyActivityPage, ProxyError> {
    validate_scope(&query.scope)?;
    let (offset, _) = parse_activity_cursor(&query.page_token)?;
    let limit = i64::try_from(query.page_size.max(1))
        .map_err(|_| super::super::shared::configuration_error())?;
    let mut client = store
        .client
        .lock()
        .map_err(|_| super::super::shared::configuration_error())?;
    let proxy = load_proxy(&mut *client, &query.proxy_id.to_string(), None)?;
    ensure_scope_match(&proxy.scope, &query.scope)?;
    let rows = client
        .query(
            "SELECT transition_id, request_id, proxy_id, revision_id, occurred_at_micros,
                actor_id, operation, prior_state, next_state, reason_code, status
         FROM mcp_proxy_lifecycle_transitions
         WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3
         ORDER BY occurred_at_micros ASC, transition_id ASC OFFSET $4 LIMIT $5",
            &[
                &query.scope.workspace_id,
                &query.scope.namespace_id,
                query.proxy_id.as_uuid(),
                &i64::try_from(offset).map_err(|_| super::super::shared::configuration_error())?,
                &(limit + 1),
            ],
        )
        .map_err(|_| ProxyError::activity_unavailable())?;
    let has_more = rows.len() > query.page_size.max(1);
    let mut activity = Vec::with_capacity(query.page_size.max(1));
    for row in rows.into_iter().take(query.page_size.max(1)) {
        activity.push(ProxyActivity {
            activity_id: row.get::<_, uuid::Uuid>(0).hyphenated().to_string(),
            request_id: row
                .get::<_, Option<uuid::Uuid>>(1)
                .map(|id| id.hyphenated().to_string())
                .unwrap_or_default(),
            scope: query.scope.clone(),
            proxy_id: query.proxy_id.clone(),
            revision_id: row
                .get::<_, Option<uuid::Uuid>>(3)
                .map(|id| super::super::ProxyRevisionId::new(id.hyphenated().to_string()))
                .transpose()
                .map_err(|_| super::super::shared::configuration_error())?,
            occurred_at: super::super::shared::format_rfc3339_micros(
                u128::try_from(row.get::<_, i64>(4))
                    .map_err(|_| super::super::shared::configuration_error())?,
            ),
            actor_id: row.get(5),
            operation: row.get(6),
            prior_state: row
                .get::<_, Option<String>>(7)
                .as_deref()
                .map(super::rows::text_to_state)
                .transpose()?,
            next_state: super::rows::text_to_state(row.get::<_, String>(8).as_str())?,
            reason_code: row.get(9),
            status: row.get(10),
        });
    }
    let next_page_token = if has_more {
        list_activity_cursor(offset + query.page_size.max(1))
    } else {
        String::new()
    };
    Ok(ListProxyActivityPage {
        activity,
        next_page_token,
    })
}
