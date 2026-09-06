//! One exact-scope transaction for management acceptance; no physical effects.
use super::super::{
    AcceptedManagedLifecycle, ManagedLifecycleAction as Action, ManagedLifecycleInput,
};
use super::{
    PostgresProxyStore, configuration_error, load_proxy, operation_journal as journal,
    query_proxy_for_update, query_revision_row,
};
use crate::proto;
use crate::proxy::{ApprovalMode, ProxyError, ProxyLifecycleEvent, ProxyLifecycleState as State};
use apex_durability::{PostgresClientOps, PostgresTransaction};
use prost::Message;
use uuid::Uuid;

mod publication;

pub(super) fn accept(
    store: &PostgresProxyStore,
    input: &ManagedLifecycleInput,
) -> Result<AcceptedManagedLifecycle, ProxyError> {
    let (request, semantic_hash) = validated_semantics(input)?;
    let mut client = store.client.try_lock().map_err(|_| configuration_error())?;
    let mut tx = client.transaction().map_err(|_| configuration_error())?;
    let target = journal::Target {
        scope: &input.scope,
        proxy_id: &input.proxy_id,
    };
    let locked = journal::lock_proxy(&mut tx, target)?;
    // Resolve original semantics before sampling the current generation or constructing new evidence.
    if let Some(accepted) = retry(&mut tx, input, &request, &semantic_hash)? {
        tx.commit().map_err(|_| configuration_error())?;
        return Ok(accepted);
    }
    let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
        .ok_or_else(ProxyError::proxy_not_found)?;
    if proxy.active_revision_id != input.expected_revision_id {
        return Err(ProxyError::revision_conflict());
    }
    if !matches!(input.action, Action::Deploy)
        && proxy.active_revision_id.as_ref() != Some(&input.revision_id)
    {
        return Err(ProxyError::revision_conflict());
    }
    let source = query_revision_row(&mut tx, &input.proxy_id, &input.revision_id)?
        .ok_or_else(ProxyError::revision_not_found)?;
    if !source.published {
        return Err(ProxyError::immutable_revision());
    }
    let generation = u64::try_from(locked.get::<_, i64>(1)).map_err(|_| configuration_error())?;
    let projection = eligibility(proxy.lifecycle_state, generation, &input.action)?;
    let (desired, action_name) = action(&input.action);
    let now = u64::try_from(journal::database_now(&mut tx)?).map_err(|_| configuration_error())?;
    let revision = publication::select(&mut tx, input, source.revision, now)?;
    if matches!(
        input.action,
        Action::Deploy | Action::Resume | Action::Rotate { .. } | Action::Rollback { .. }
    ) && revision.spec.governance_binding.approval_mode != ApprovalMode::None
        && !input.approved
    {
        return Err(ProxyError::approval_required());
    }
    let evidence = crate::proxy::events::managed_event(
        &ProxyLifecycleEvent {
            request_id: input.request_id.clone(),
            operation: action_name.into(),
            scope: input.scope.clone(),
            proxy_id: input.proxy_id.clone(),
            revision_id: Some(revision.revision_id.clone()),
            actor_id: input.actor_id.clone(),
            reason_code: input.reason_code.clone(),
        },
        &Uuid::now_v7().to_string(),
        now,
    )?;
    let operation = journal::submit_operation(
        &mut tx,
        &journal::SubmitOperation {
            target,
            request_id: &input.request_id,
            expected_revision_id: input.expected_revision_id.as_ref(),
            revision_id: &revision.revision_id,
            expected_generation: generation,
            desired_state: desired,
            evidence: &evidence,
        },
    )?;
    tx.execute("UPDATE mcp_proxies SET lifecycle_state=$4 WHERE workspace_id=$1 AND namespace_id=$2 AND proxy_id=$3",
        &[&input.scope.workspace_id, &input.scope.namespace_id, input.proxy_id.as_uuid(), &super::rows::state_to_text(projection)])
        .map_err(|_| configuration_error())?;
    super::insert_lifecycle_transition(
        &mut tx,
        action_name,
        &input.scope,
        &input.proxy_id,
        Some(&revision.revision_id),
        Some(proxy.lifecycle_state),
        projection,
        Some(&input.actor_id),
        &input.reason_code,
        "accepted",
        u128::from(now),
        Some(&input.request_id),
    )?;
    let result = AcceptedManagedLifecycle {
        proxy: crate::proxy::service::proxy_to_proto(load_proxy(
            &mut tx,
            &input.proxy_id.to_string(),
            None,
        )?),
        revision: crate::proxy::service::revision_to_proto(revision),
        operation,
    };
    tx.execute("INSERT INTO mcp_proxy_managed_acceptance (request_id,operation_id,semantic_hash,proxy_snapshot,revision_snapshot) VALUES ($1,$2,$3,$4,$5)",
        &[&request, &journal::request_uuid(&result.operation.operation_id)?, &semantic_hash,
        &result.proxy.encode_to_vec(), &result.revision.encode_to_vec()]).map_err(|_| configuration_error())?;
    tx.commit().map_err(|_| configuration_error())?;
    Ok(result)
}

/// Resolve committed acceptance before mutable approval/revision dependencies.
/// A miss grants no authority: accept repeats this check under its transaction.
pub(super) fn accepted_retry(
    store: &PostgresProxyStore,
    input: &ManagedLifecycleInput,
) -> Result<Option<AcceptedManagedLifecycle>, ProxyError> {
    let (request, hash) = validated_semantics(input)?;
    let mut client = store.client.try_lock().map_err(|_| configuration_error())?;
    let mut tx = client.transaction().map_err(|_| configuration_error())?;
    journal::lock_proxy(
        &mut tx,
        journal::Target {
            scope: &input.scope,
            proxy_id: &input.proxy_id,
        },
    )?;
    let accepted = retry(&mut tx, input, &request, &hash)?;
    tx.commit().map_err(|_| configuration_error())?;
    Ok(accepted)
}

fn validated_semantics(input: &ManagedLifecycleInput) -> Result<(Uuid, String), ProxyError> {
    let request = journal::request_uuid(&input.request_id)?;
    super::super::shared::validate_scope(&input.scope)?;
    crate::proxy::validation::bounded_required_string(input.actor_id.clone())?;
    super::super::shared::validate_reason_code(input.reason_code.clone())?;
    // Preserve the existing durable reason-code grammar (not worker IDs).
    if !input
        .reason_code
        .starts_with(|c: char| c.is_ascii_lowercase())
        || input.reason_code.contains('/')
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Invalid lifecycle reason code.",
        ));
    }
    Ok((request, semantics(input)?))
}

fn retry(
    tx: &mut PostgresTransaction<'_>,
    input: &ManagedLifecycleInput,
    request: &Uuid,
    hash: &str,
) -> Result<Option<AcceptedManagedLifecycle>, ProxyError> {
    let row = tx
        .query_opt(
            "SELECT a.semantic_hash,a.proxy_snapshot,a.revision_snapshot,o.accepted_result,
        o.workspace_id,o.namespace_id,o.proxy_id FROM mcp_proxy_managed_acceptance a
        JOIN mcp_proxy_operations o USING(operation_id) WHERE a.request_id=$1",
            &[request],
        )
        .map_err(|_| configuration_error())?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != hash
        || row.get::<_, String>(4) != input.scope.workspace_id
        || row.get::<_, String>(5) != input.scope.namespace_id
        || row.get::<_, Uuid>(6) != *input.proxy_id.as_uuid()
    {
        return Err(ProxyError::idempotency_conflict());
    }
    Ok(Some(AcceptedManagedLifecycle {
        proxy: proto::McpProxy::decode(row.get::<_, Vec<u8>>(1).as_slice())
            .map_err(|_| configuration_error())?,
        revision: proto::McpProxyRevision::decode(row.get::<_, Vec<u8>>(2).as_slice())
            .map_err(|_| configuration_error())?,
        operation: proto::ProxyOperation::decode(row.get::<_, Vec<u8>>(3).as_slice())
            .map_err(|_| configuration_error())?,
    }))
}

fn semantics(input: &ManagedLifecycleInput) -> Result<String, ProxyError> {
    let mut refs = match &input.action {
        Action::Rotate { secret_refs } => {
            if secret_refs.is_empty() || secret_refs.len() > crate::proxy::MAX_SECRET_REFS {
                return Err(ProxyError::invalid_proxy_spec(
                    "Invalid rotation references.",
                ));
            }
            secret_refs.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        }
        _ => vec![],
    };
    refs.sort_unstable();
    if refs.windows(2).any(|r| r[0] == r[1]) {
        return Err(ProxyError::invalid_proxy_spec(
            "Duplicate rotation references.",
        ));
    }
    Ok(super::super::shared::hash_hex(serde_json::json!({
        "scope": [&input.scope.workspace_id, &input.scope.namespace_id], "proxy": input.proxy_id.to_string(),
        "revision": input.revision_id.to_string(), "expected": input.expected_revision_id.as_ref().map(ToString::to_string),
        "actor": input.actor_id, "reason": input.reason_code, "action": action(&input.action).1,
        "references": refs, "target": match &input.action { Action::Rollback {target_revision_id} => Some(target_revision_id.to_string()), _ => None },
    }).to_string().as_bytes()))
}

pub(super) fn action(action: &Action) -> (proto::ProxyDesiredState, &'static str) {
    use proto::ProxyDesiredState::*;
    match action {
        Action::Deploy => (Serving, "deploy_proxy"),
        Action::Resume => (Serving, "resume_proxy"),
        Action::Pause => (Paused, "pause_proxy"),
        Action::Retire => (Retired, "retire_proxy"),
        Action::Rotate { .. } => (Serving, "rotate_proxy_credentials"),
        Action::Rollback { .. } => (Serving, "rollback_proxy"),
    }
}

fn eligibility(state: State, generation: u64, action: &Action) -> Result<State, ProxyError> {
    if state == State::Retired || (state == State::Retiring && !matches!(action, Action::Retire)) {
        return Err(ProxyError::invalid_lifecycle_transition());
    }
    let allowed = match action {
        Action::Deploy => state == State::AwaitingApproval || generation > 0,
        Action::Resume => state == State::Paused,
        Action::Pause | Action::Retire | Action::Rotate { .. } | Action::Rollback { .. } => {
            generation > 0
        }
    };
    if !allowed {
        return Err(ProxyError::invalid_lifecycle_transition());
    }
    // Existing wire has no Pausing; Provisioning is explicitly nonterminal.
    Ok(if matches!(action, Action::Retire) {
        State::Retiring
    } else {
        State::Provisioning
    })
}
