//! Transactional journal primitives. Callers authorize lifecycle changes and relay
//! stored evidence through the existing Apex outbox after commit.

use super::super::shared::{configuration_error, hash_hex, validate_request_id, validate_scope};
use crate::ExactScope;
use crate::proto::{ProxyDesiredState, ProxyObservedState, ProxyOperation, ProxyResourceScope};
use crate::proxy::{ProxyError, ProxyId, ProxyRevisionId};
use apex_durability::{IngestRequest, proto::EventEnvelope};
use apex_durability::{PostgresClientOps as GenericClient, PostgresTransaction as Transaction};
use postgres::Row;
use prost::Message;
use uuid::Uuid;

mod leases;
mod live_lease;
mod validation;
pub(super) use leases::lease_operation;
pub(super) use live_lease::exact_live_lease_expiry;
use validation::validate_observation;
pub(super) use validation::{bounded_identifier, desired_text};

#[derive(Clone, Copy)]
pub(super) struct Target<'a> {
    pub scope: &'a ExactScope,
    pub proxy_id: &'a ProxyId,
}

pub(super) struct SubmitOperation<'a> {
    pub target: Target<'a>,
    pub request_id: &'a str,
    pub expected_revision_id: Option<&'a ProxyRevisionId>,
    pub revision_id: &'a ProxyRevisionId,
    pub expected_generation: u64,
    pub desired_state: ProxyDesiredState,
    pub evidence: &'a EventEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct LeasedOperation {
    pub operation: ProxyOperation,
    pub worker_id: String,
    pub fencing_token: u64,
    pub lease_expires_at_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingEvidenceIntent {
    pub operation_id: Uuid,
    pub intent: EvidenceIntent,
}

/// Commit acceptance, desired state and evidence together. GenericClient starts
/// a transaction for Client and a rollback-on-error savepoint for Transaction.
pub(super) fn submit_operation(
    client: &mut impl GenericClient,
    input: &SubmitOperation<'_>,
) -> Result<ProxyOperation, ProxyError> {
    let request = request_uuid(input.request_id)?;
    let target = input.target;
    let generation = sql_u64(input.expected_generation)?
        .checked_add(1)
        .ok_or_else(ProxyError::revision_conflict)?;
    let desired = desired_text(input.desired_state)?;
    let intent = validated_intent(target, input.request_id, input.evidence)?;
    // Exclude regenerated event ID/time from retry identity, never from stored evidence.
    let mut semantic_event = input.evidence.clone();
    semantic_event.event_id = input.request_id.to_owned();
    semantic_event.timestamp.clear();
    let semantic_hash = apex_durability::canonical_event_hash(&semantic_event)
        .map_err(|_| configuration_error())?;
    let hash = hash_hex(
        serde_json::json!({
            "request": input.request_id, "workspace": target.scope.workspace_id,
            "namespace": target.scope.namespace_id, "proxy": target.proxy_id.to_string(),
            "expected_revision": input.expected_revision_id.map(ToString::to_string),
            "revision": input.revision_id.to_string(), "generation": input.expected_generation,
            "desired": desired, "evidence": semantic_hash
        })
        .to_string()
        .as_bytes(),
    );
    let mut tx = client.transaction().map_err(db_error)?;
    let locked = lock_proxy(&mut tx, target)?;
    if let Some(row) = tx
        .query_opt(
            "SELECT request_hash, accepted_result FROM mcp_proxy_operations
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3 AND request_id = $4",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &request,
            ],
        )
        .map_err(db_error)?
    {
        if row.get::<_, String>(0) != hash {
            return Err(ProxyError::idempotency_conflict());
        }
        let result = decode_result(&row, "accepted_result")?;
        tx.commit().map_err(db_error)?;
        return Ok(result);
    }
    let expected = input.expected_revision_id.map(ProxyRevisionId::as_uuid);
    if locked.get::<_, Option<Uuid>>(0).as_ref() != expected
        || locked.get::<_, i64>(1) != generation - 1
    {
        return Err(ProxyError::revision_conflict());
    }
    let published = tx
        .query_opt(
            "SELECT r.is_published FROM mcp_proxy_revisions r
        JOIN mcp_proxies p ON p.proxy_id = r.proxy_id WHERE p.workspace_id = $1
        AND p.namespace_id = $2 AND p.proxy_id = $3 AND r.revision_id = $4",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                input.revision_id.as_uuid(),
            ],
        )
        .map_err(db_error)?
        .ok_or_else(ProxyError::revision_not_found)?;
    if !published.get::<_, bool>(0) {
        return Err(ProxyError::immutable_revision());
    }
    let operation_id = Uuid::now_v7();
    let result = ProxyOperation {
        operation_id: operation_id.to_string(),
        request_id: input.request_id.to_owned(),
        scope: Some(ProxyResourceScope {
            workspace_id: target.scope.workspace_id.clone(),
            namespace_id: target.scope.namespace_id.clone(),
            proxy_id: target.proxy_id.to_string(),
        }),
        revision_id: input.revision_id.to_string(),
        desired_state: input.desired_state as i32,
        observed_state: ProxyObservedState::Pending as i32,
        generation: input.expected_generation + 1,
        error_code: String::new(),
        observed_at_unix_us: 0,
    };
    let changed = tx
        .execute(
            "UPDATE mcp_proxies SET active_revision_id = $4, desired_state = $5,
        deployment_generation = $6 WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3
        AND active_revision_id IS NOT DISTINCT FROM $7 AND deployment_generation = $8",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                input.revision_id.as_uuid(),
                &desired,
                &generation,
                &expected,
                &(generation - 1),
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(ProxyError::revision_conflict());
    }
    let now = database_now(&mut tx)?;
    tx.execute(
        "INSERT INTO mcp_proxy_operations (workspace_id, namespace_id, proxy_id,
        operation_id, request_id, revision_id, expected_revision_id, generation, desired_state,
        request_hash, accepted_result, current_result, created_at_micros)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12)",
        &[
            &target.scope.workspace_id,
            &target.scope.namespace_id,
            target.proxy_id.as_uuid(),
            &operation_id,
            &request,
            input.revision_id.as_uuid(),
            &expected,
            &generation,
            &desired,
            &hash,
            &result.encode_to_vec(),
            &now,
        ],
    )
    .map_err(db_error)?;
    insert_intent(&mut tx, target, &result, &intent)?;
    tx.commit().map_err(db_error)?;
    Ok(result)
}

pub(super) fn get_operation(
    client: &mut impl GenericClient,
    target: Target<'_>,
    id: &str,
) -> Result<Option<ProxyOperation>, ProxyError> {
    validate_scope(target.scope)?;
    let id = request_uuid(id)?;
    client
        .query_opt(
            "SELECT current_result FROM mcp_proxy_operations WHERE workspace_id = $1
        AND namespace_id = $2 AND proxy_id = $3 AND operation_id = $4",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &id,
            ],
        )
        .map_err(db_error)?
        .map(|row| decode_result(&row, "current_result"))
        .transpose()
}

/// Commit observation/evidence atomically; even retries require the live fence.
pub(super) fn observe_operation(
    client: &mut impl GenericClient,
    target: Target<'_>,
    lease: &LeasedOperation,
    state: ProxyObservedState,
    error: Option<&str>,
    event: &EventEnvelope,
) -> Result<ProxyOperation, ProxyError> {
    if matches!(
        state,
        ProxyObservedState::Unspecified | ProxyObservedState::Pending
    ) || error.is_some_and(|value| !bounded_identifier(value))
    {
        return Err(ProxyError::invalid_proxy_spec("Invalid proxy observation."));
    }
    let operation_id = request_uuid(&lease.operation.operation_id)?;
    let generation = sql_u64(lease.operation.generation)?;
    let fence = sql_u64(lease.fencing_token)?;
    let intent = validated_intent(target, &lease.operation.request_id, event)?;
    let mut tx = client.transaction().map_err(db_error)?;
    let locked = lock_proxy(&mut tx, target)?;
    if locked.get::<_, i64>(1) != generation {
        return Err(stale_fence());
    }
    let now = database_now(&mut tx)?;
    let valid = exact_live_lease_expiry(
        &mut tx,
        target,
        &operation_id,
        generation,
        &lease.worker_id,
        fence,
        now,
    )?;
    if valid.is_none() {
        return Err(stale_fence());
    }
    let mut result =
        get_operation(&mut tx, target, &lease.operation.operation_id)?.ok_or_else(stale_fence)?;
    if result.revision_id != lease.operation.revision_id
        || result.request_id != lease.operation.request_id
        || !matches_live_target(&locked, &result)?
    {
        return Err(stale_fence());
    }
    // Validate the durable desired state, never the caller's lease snapshot.
    validate_observation(result.desired_state, state)?;
    if let Some(row) = tx
        .query_opt(
            "SELECT payload_hash, operation_result FROM mcp_proxy_evidence_intents
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3
        AND operation_id = $4 AND event_id = $5",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &operation_id,
                &intent.event_id,
            ],
        )
        .map_err(db_error)?
    {
        let original = decode_result(&row, "operation_result")?;
        if row.get::<_, String>(0) != intent.payload_hash
            || original.observed_state != state as i32
            || original.error_code != error.unwrap_or_default()
        {
            return Err(ProxyError::idempotency_conflict());
        }
        tx.commit().map_err(db_error)?;
        return Ok(original);
    }
    // Completed commands retain exact-event retries, but cannot accept new observations.
    if matches!(
        ProxyObservedState::try_from(result.observed_state).map_err(|_| configuration_error())?,
        ProxyObservedState::Ready | ProxyObservedState::Paused | ProxyObservedState::Retired
    ) {
        return Err(ProxyError::invalid_lifecycle_transition());
    }
    result.observed_state = state as i32;
    result.error_code = error.unwrap_or_default().to_owned();
    result.observed_at_unix_us = u64::try_from(now).map_err(|_| configuration_error())?;
    let changed = tx
        .execute(
            "UPDATE mcp_proxy_operations SET current_result = $5,
        observed_state = $6, observed_at_micros = $7 WHERE workspace_id = $1 AND namespace_id = $2
        AND proxy_id = $3 AND operation_id = $4 AND generation = $8 AND observed_at_micros <= $7",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &operation_id,
                &result.encode_to_vec(),
                &(state as i32),
                &now,
                &generation,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(stale_fence());
    }
    let changed = tx
        .execute(
            "UPDATE mcp_proxies SET observed_status = $4 WHERE workspace_id = $1
        AND namespace_id = $2 AND proxy_id = $3 AND deployment_generation = $5",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &state.as_str_name(),
                &generation,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(stale_fence());
    }
    insert_intent(&mut tx, target, &result, &intent)?;
    tx.commit().map_err(db_error)?;
    Ok(result)
}

/// Read bounded relay batches; unmarked retries retain original bytes and hash.
pub(super) fn pending_evidence_intents(
    client: &mut impl GenericClient,
    target: Target<'_>,
    limit: u32,
) -> Result<Vec<PendingEvidenceIntent>, ProxyError> {
    validate_scope(target.scope)?;
    if !(1..=256).contains(&limit) {
        return Err(ProxyError::invalid_cursor());
    }
    client.query("SELECT operation_id, event_id, event_timestamp, canonical_payload, payload_hash
        FROM mcp_proxy_evidence_intents WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3
        AND enqueued_at_micros IS NULL ORDER BY event_timestamp, event_id LIMIT $4",
        &[&target.scope.workspace_id, &target.scope.namespace_id, target.proxy_id.as_uuid(), &i64::from(limit)])
        .map_err(db_error)?.into_iter().map(|row| {
            let event = EventEnvelope::decode(row.get::<_, Vec<u8>>(3).as_slice())
                .map_err(|_| configuration_error())?;
            let mut intent = EvidenceIntent::new(target, &event)?;
            if intent.event_id != row.get::<_, Uuid>(1) || intent.event_timestamp != row.get::<_, String>(2)
                || intent.payload_hash != row.get::<_, String>(4) { return Err(configuration_error()); }
            intent.envelope = row.get(3); // Preserve original serialization, including map ordering.
            Ok(PendingEvidenceIntent { operation_id: row.get(0), intent })
        }).collect()
}

/// Mark after outbox acceptance; false means no matching pending event.
pub(super) fn mark_evidence_enqueued(
    client: &mut impl GenericClient,
    target: Target<'_>,
    operation: &str,
    event: &str,
    hash: &str,
) -> Result<bool, ProxyError> {
    validate_scope(target.scope)?;
    let operation = request_uuid(operation)?;
    let event = request_uuid(event)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProxyError::invalid_proxy_spec("Invalid evidence hash."));
    }
    client
        .execute(
            "UPDATE mcp_proxy_evidence_intents SET enqueued_at_micros =
        floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint WHERE workspace_id = $1
        AND namespace_id = $2 AND proxy_id = $3 AND operation_id = $4 AND event_id = $5
        AND payload_hash = $6 AND enqueued_at_micros IS NULL",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &operation,
                &event,
                &hash,
            ],
        )
        .map(|count| count == 1)
        .map_err(db_error)
}

fn insert_intent(
    tx: &mut Transaction<'_>,
    target: Target<'_>,
    result: &ProxyOperation,
    intent: &EvidenceIntent,
) -> Result<(), ProxyError> {
    let operation = request_uuid(&result.operation_id)?;
    tx.execute(
        "INSERT INTO mcp_proxy_evidence_intents (workspace_id, namespace_id, proxy_id,
        operation_id, event_id, event_timestamp, canonical_payload, payload_hash, operation_result)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[
            &target.scope.workspace_id,
            &target.scope.namespace_id,
            target.proxy_id.as_uuid(),
            &operation,
            &intent.event_id,
            &intent.event_timestamp,
            &intent.envelope,
            &intent.payload_hash,
            &result.encode_to_vec(),
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(super) fn lock_proxy(tx: &mut Transaction<'_>, target: Target<'_>) -> Result<Row, ProxyError> {
    validate_scope(target.scope)?;
    tx.query_opt(
        "SELECT active_revision_id, deployment_generation, desired_state FROM mcp_proxies
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3 FOR UPDATE",
        &[
            &target.scope.workspace_id,
            &target.scope.namespace_id,
            target.proxy_id.as_uuid(),
        ],
    )
    .map_err(db_error)?
    .ok_or_else(ProxyError::proxy_not_found)
}

/// The proxy row stays locked until commit. Legacy lifecycle writes can change
/// its desired state or active revision without incrementing the generation.
pub(super) fn matches_live_target(
    locked: &Row,
    operation: &ProxyOperation,
) -> Result<bool, ProxyError> {
    let desired =
        ProxyDesiredState::try_from(operation.desired_state).map_err(|_| configuration_error())?;
    Ok(
        locked.get::<_, Option<Uuid>>(0) == Some(request_uuid(&operation.revision_id)?)
            && locked.get::<_, i64>(1) == sql_u64(operation.generation)?
            && locked.get::<_, String>(2) == desired_text(desired)?,
    )
}

fn validated_intent(
    target: Target<'_>,
    request: &str,
    event: &EventEnvelope,
) -> Result<EvidenceIntent, ProxyError> {
    if event.event_id == request || event.run_id != request || event.r#type != 7 {
        return Err(ProxyError::invalid_proxy_spec(
            "Evidence requires a unique workflow event and request correlation.",
        ));
    }
    EvidenceIntent::new(target, event)
}

pub(super) fn request_uuid(value: &str) -> Result<Uuid, ProxyError> {
    validate_request_id(value)?;
    let id = ProxyRevisionId::new(value).map_err(|_| ProxyError::invalid_request_id())?;
    Ok(*id.as_uuid())
}

fn decode_result(row: &Row, column: &str) -> Result<ProxyOperation, ProxyError> {
    ProxyOperation::decode(row.get::<_, Vec<u8>>(column).as_slice())
        .map_err(|_| configuration_error())
}

pub(super) fn database_now(tx: &mut Transaction<'_>) -> Result<i64, ProxyError> {
    tx.query_one(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
        &[],
    )
    .map(|row| row.get(0))
    .map_err(db_error)
}

fn sql_u64(value: u64) -> Result<i64, ProxyError> {
    i64::try_from(value).map_err(|_| ProxyError::revision_conflict())
}

fn stale_fence() -> ProxyError {
    ProxyError::new(
        "PROXY_STALE_FENCE",
        "The proxy lease or generation is no longer current.",
    )
}

fn db_error(error: apex_durability::PostgresClientError) -> ProxyError {
    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
        ProxyError::idempotency_conflict()
    } else {
        configuration_error()
    }
}

/// Validated EventEnvelope v1; payload_hash is Apex's canonical event hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EvidenceIntent {
    pub event_id: Uuid,
    pub event_timestamp: String,
    pub envelope: Vec<u8>,
    pub payload_hash: String,
}

impl EvidenceIntent {
    pub(super) fn new(target: Target<'_>, event: &EventEnvelope) -> Result<Self, ProxyError> {
        validate_scope(target.scope)?;
        let request = IngestRequest::from_validated_transport_ref(event)
            .map_err(|_| ProxyError::invalid_proxy_spec("Invalid proxy evidence envelope."))?;
        let data = event.data.as_ref().ok_or_else(configuration_error)?;
        let proxy_id = data.fields.get("proxy_id");
        if request.workspace_id() != target.scope.workspace_id
            || request.namespace_id() != target.scope.namespace_id
            || !matches!(proxy_id.and_then(|value| value.kind.as_ref()),
                Some(prost_types::value::Kind::StringValue(id)) if id == &target.proxy_id.to_string())
        {
            return Err(ProxyError::invalid_proxy_scope());
        }
        let integrity = event.integrity.as_ref().ok_or_else(configuration_error)?;
        Ok(Self {
            event_id: request_uuid(request.event_id())?,
            event_timestamp: event.timestamp.clone(),
            envelope: request.envelope().to_vec(),
            payload_hash: integrity.event_hash.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
