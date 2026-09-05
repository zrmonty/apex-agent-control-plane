//! Point-in-time store data only: not authenticated runtime authority, an
//! execution permit, installation ownership, readiness, or lease renewal.
//!
//! Future callers must independently authenticate current peer/policy, map the
//! controller to its worker, and verify installation enrollment. They must own
//! bounded blocking dispatch/cancellation and recheck authority before effects.
//! Per-query transport/lock timeouts are not a whole-transaction/job deadline;
//! a successful committed snapshot cannot solve lease-to-engine TOCTOU.

use super::super::publish_capabilities::validate_publish_capabilities;
use super::super::shared::{configuration_error, hash_hex, spec_json, validate_scope};
use super::operation_journal::{
    Target, bounded_identifier, database_now, desired_text, exact_live_lease_expiry, lock_proxy,
    matches_live_target, request_uuid,
};
use super::{PostgresProxyStore, query_revision_row};
use crate::ExactScope;
use crate::proto::{ProxyDesiredState, ProxyObservedState, ProxyOperation, RuntimeTarget};
use crate::proxy::{McpProxyRevision, ProxyError, ProxyId, ProxyRevisionId};
use apex_durability::{PostgresClientOps, PostgresConnection, PostgresTransaction};
use postgres::{Row, types::FromSql};
use prost::Message;
use std::sync::MutexGuard;
use uuid::Uuid;

/// Copied PostgreSQL operation/revision metadata, not an authority capability.
/// Fields may be copied or edited by consumers; that creates no trusted evidence.
#[derive(Clone)]
pub struct RuntimeOperationSnapshot {
    pub operation: ProxyOperation,
    pub revision: McpProxyRevision,
    pub worker_id: String,
    pub fencing_token: u64,
    /// Database clock sample after all validation, immediately before commit.
    pub checked_at_unix_us: u64,
    /// Exact stored lease expiry, not caller time or a newly issued lease.
    pub lease_expires_at_unix_us: u64,
}

impl std::fmt::Debug for RuntimeOperationSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // In particular, do not format the revision's material references/spec.
        f.debug_struct("RuntimeOperationSnapshot")
            .finish_non_exhaustive()
    }
}

impl PostgresProxyStore {
    /// Cooperative checkpoint sibling for the dedicated runtime-authority owner.
    ///
    /// The owner checks cancellation, elapsed deadline and current policy. A
    /// refusal is propagated unchanged after any transaction cleanup completes.
    /// An in-flight query still uses the existing transport bounds; this does
    /// not physically preempt PostgreSQL or grant future execution authority.
    pub(crate) fn read_current_runtime_operation_checked(
        &self,
        target: &RuntimeTarget,
        operation_id: &str,
        worker_id: &str,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<RuntimeOperationSnapshot, ProxyError> {
        read_checked(
            || self.client.try_lock_checked(check),
            target,
            operation_id,
            worker_id,
            check,
        )
    }

    /// Read exact current operation data using generated target fields as claims.
    ///
    /// This synchronous store seam has no RPC or runtime-effect caller. It does
    /// not authenticate a peer or promise freshness after transaction commit.
    ///
    /// # Errors
    /// Returns static errors for invalid claims, noncurrent/corrupt stored data,
    /// or dependency failures. Invalid claims are rejected before DB resources;
    /// a busy store refuses immediately. Query bounds are not a job deadline.
    pub fn read_current_runtime_operation(
        &self,
        target: &RuntimeTarget,
        operation_id: &str,
        worker_id: &str,
    ) -> Result<RuntimeOperationSnapshot, ProxyError> {
        read_checked(
            || self.client.try_lock().map_err(|_| configuration_error()),
            target,
            operation_id,
            worker_id,
            &|| Ok(()),
        )
    }
}

// The private acquisition seam can only yield the existing real connection
// guard. Tests can refuse/panic before acquisition without constructing a DB;
// this does not accept an alternative SQL backend or arbitrary job executor.
fn read_checked<'a>(
    acquire_connection: impl FnOnce() -> Result<MutexGuard<'a, PostgresConnection>, ProxyError>,
    target: &RuntimeTarget,
    operation_id: &str,
    worker_id: &str,
    check: &impl Fn() -> Result<(), ProxyError>,
) -> Result<RuntimeOperationSnapshot, ProxyError> {
    let scope = ExactScope {
        workspace_id: target.workspace_id.clone(),
        namespace_id: target.namespace_id.clone(),
    };
    validate_scope(&scope).map_err(|_| invalid_claims())?;
    let proxy_id = ProxyId::new(&target.proxy_id).map_err(|_| invalid_claims())?;
    let revision_id = ProxyRevisionId::new(&target.revision_id).map_err(|_| invalid_claims())?;
    let operation_id = request_uuid(operation_id).map_err(|_| invalid_claims())?;
    let generation = positive_sql(target.generation)?;
    let fence = positive_sql(target.fencing_token)?;
    if !bounded_identifier(worker_id) {
        return Err(invalid_claims());
    }
    let scoped = Target {
        scope: &scope,
        proxy_id: &proxy_id,
    };
    check()?;
    let mut client = acquire_connection()?;
    check()?;
    let mut tx = client.transaction().map_err(|_| configuration_error())?;
    // On any early return, tx drops before client and completes synchronous
    // rollback/transport cleanup under the lock. Cleanup is never checkpointed.
    check()?;
    let locked = lock_proxy(&mut tx, scoped).map_err(stored_error)?;
    check()?;
    let now = database_now(&mut tx)?;
    check()?;
    let expiry = exact_live_lease_expiry(
        &mut tx,
        scoped,
        &operation_id,
        generation,
        worker_id,
        fence,
        now,
    )?
    .ok_or_else(not_current)?;
    check()?;
    let operation = read_operation(&mut tx, scoped, target, &operation_id)?;
    if !matches_live_target(&locked, &operation).map_err(stored_error)? {
        return Err(not_current());
    }
    // Unlike load_revision/get_revision, this retains the publication flag.
    // The real publisher stamps lifecycle Draft; it is not publication proof.
    check()?;
    let stored = query_revision_row(&mut tx, &proxy_id, &revision_id)
        .map_err(stored_error)?
        .ok_or_else(not_current)?;
    if !stored.published
        || stored.revision.proxy_id != proxy_id
        || stored.revision.revision_id != revision_id
    {
        return Err(not_current());
    }
    validate_publish_capabilities(&stored.revision.spec).map_err(|_| not_current())?;
    if hash_hex(spec_json(&stored.revision.spec).as_bytes()) != stored.revision.config_hash {
        return Err(not_current());
    }
    let lease_expires_at_unix_us = u64::try_from(expiry).map_err(|_| not_current())?;
    // Last database sample follows every read/validation. Never authorize
    // with the earlier lease-check time if the lease expired during a query.
    check()?;
    let checked_at_unix_us =
        u64::try_from(database_now(&mut tx)?).map_err(|_| configuration_error())?;
    if checked_at_unix_us >= lease_expires_at_unix_us {
        return Err(not_current());
    }
    check()?;
    tx.commit().map_err(|_| configuration_error())?;
    let snapshot = RuntimeOperationSnapshot {
        operation,
        revision: stored.revision,
        worker_id: worker_id.to_owned(),
        fencing_token: target.fencing_token,
        checked_at_unix_us,
        lease_expires_at_unix_us,
    };
    drop(client);
    // A cancellation racing read-only commit cannot produce a late snapshot.
    check()?;
    Ok(snapshot)
}

fn read_operation(
    tx: &mut PostgresTransaction<'_>,
    scoped: Target<'_>,
    target: &RuntimeTarget,
    operation_id: &Uuid,
) -> Result<ProxyOperation, ProxyError> {
    let row = tx
        .query_opt(
            "SELECT workspace_id, namespace_id, proxy_id, operation_id, request_id, revision_id,
        generation, desired_state, observed_state, observed_at_micros, current_result
        FROM mcp_proxy_operations WHERE workspace_id = $1 AND namespace_id = $2
        AND proxy_id = $3 AND operation_id = $4",
            &[
                &scoped.scope.workspace_id,
                &scoped.scope.namespace_id,
                scoped.proxy_id.as_uuid(),
                operation_id,
            ],
        )
        .map_err(|_| configuration_error())?
        .ok_or_else(not_current)?;
    let bytes: &[u8] = column(&row, "current_result")?;
    if !(1..=16_384).contains(&bytes.len()) {
        return Err(not_current());
    }
    let operation = ProxyOperation::decode(bytes).map_err(|_| not_current())?;
    let scope = operation.scope.as_ref().ok_or_else(not_current)?;
    let desired =
        ProxyDesiredState::try_from(operation.desired_state).map_err(|_| not_current())?;
    let observed =
        ProxyObservedState::try_from(operation.observed_state).map_err(|_| not_current())?;
    let request_id = request_uuid(&operation.request_id).map_err(|_| not_current())?;
    let stored_generation =
        u64::try_from(column::<i64>(&row, "generation")?).map_err(|_| not_current())?;
    let observed_at =
        u64::try_from(column::<i64>(&row, "observed_at_micros")?).map_err(|_| not_current())?;
    // Compare decoded fields with BOTH claims and independently selected row
    // columns. A well-formed protobuf blob alone is never current-row identity.
    if request_uuid(&operation.operation_id).map_err(|_| not_current())? != *operation_id
        || column::<Uuid>(&row, "operation_id")? != *operation_id
        || request_id != column::<Uuid>(&row, "request_id")?
        || request_id == *operation_id
        || scope.workspace_id != target.workspace_id
        || scope.workspace_id != column::<&str>(&row, "workspace_id")?
        || scope.namespace_id != target.namespace_id
        || scope.namespace_id != column::<&str>(&row, "namespace_id")?
        || scope.proxy_id != target.proxy_id
        || column::<Uuid>(&row, "proxy_id")? != *scoped.proxy_id.as_uuid()
        || operation.revision_id != target.revision_id
        || request_uuid(&operation.revision_id).map_err(|_| not_current())?
            != column::<Uuid>(&row, "revision_id")?
        || operation.generation != target.generation
        || operation.generation != stored_generation
        || desired_text(desired).map_err(|_| not_current())?
            != column::<&str>(&row, "desired_state")?
        || operation.observed_state != column::<i32>(&row, "observed_state")?
        || operation.observed_at_unix_us != observed_at
        || !matches!(
            observed,
            ProxyObservedState::Pending
                | ProxyObservedState::Reconciling
                | ProxyObservedState::Failed
                | ProxyObservedState::NotServing
        )
        || (!operation.error_code.is_empty() && !bounded_identifier(&operation.error_code))
    {
        return Err(not_current());
    }
    Ok(operation)
}

fn column<'a, T: FromSql<'a>>(row: &'a Row, name: &str) -> Result<T, ProxyError> {
    row.try_get(name).map_err(|_| configuration_error())
}

fn positive_sql(value: u64) -> Result<i64, ProxyError> {
    if value == 0 {
        return Err(invalid_claims());
    }
    i64::try_from(value).map_err(|_| invalid_claims())
}

// Existing row/query helpers already collapse transport and some incompatible
// storage errors to this static code. Preserve it; never expose their inputs.
fn stored_error(error: ProxyError) -> ProxyError {
    if error.code() == "PROXY_STORE_UNAVAILABLE" {
        configuration_error()
    } else {
        not_current()
    }
}

fn invalid_claims() -> ProxyError {
    ProxyError::new(
        "INVALID_RUNTIME_OPERATION_CLAIMS",
        "Invalid runtime operation claims.",
    )
}

fn not_current() -> ProxyError {
    ProxyError::new(
        "PROXY_RUNTIME_OPERATION_NOT_CURRENT",
        "The stored runtime operation is not current or valid.",
    )
}

#[cfg(test)]
mod store_cancellation_tests;
