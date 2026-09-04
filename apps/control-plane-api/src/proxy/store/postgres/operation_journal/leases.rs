//! Claims require the live proxy target and a persistent, increasing fence.

use super::{
    LeasedOperation, Target, bounded_identifier, configuration_error, database_now, db_error,
    decode_result, lock_proxy, matches_live_target,
};
use crate::proxy::ProxyError;
use apex_durability::PostgresClientOps as GenericClient;
use std::time::Duration;
use uuid::Uuid;

/// Claim the current generation with database time and a persistent fencing counter.
pub(in super::super) fn lease_operation(
    client: &mut impl GenericClient,
    target: Target<'_>,
    worker: &str,
    ttl: Duration,
) -> Result<Option<LeasedOperation>, ProxyError> {
    if !bounded_identifier(worker)
        || ttl.is_zero()
        || ttl > Duration::from_secs(300)
        || ttl.as_micros() == 0
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Invalid worker identity or lease duration.",
        ));
    }
    let ttl = i64::try_from(ttl.as_micros()).map_err(|_| configuration_error())?;
    let mut tx = client.transaction().map_err(db_error)?;
    let locked = lock_proxy(&mut tx, target)?;
    let generation: i64 = locked.get(1);
    let Some(row) = tx
        .query_opt(
            "SELECT operation_id, current_result FROM mcp_proxy_operations
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3 AND generation = $4
        AND observed_state IN (1,2,6,7)",
            &[
                &target.scope.workspace_id,
                &target.scope.namespace_id,
                target.proxy_id.as_uuid(),
                &generation,
            ],
        )
        .map_err(db_error)?
    else {
        return Ok(None);
    };
    let operation = decode_result(&row, "current_result")?;
    if !matches_live_target(&locked, &operation)? {
        return Ok(None);
    }
    let operation_id: Uuid = row.get(0);
    let now = database_now(&mut tx)?;
    let expires = now.checked_add(ttl).ok_or_else(configuration_error)?;
    let Some(lease) = tx.query_opt("INSERT INTO mcp_proxy_controller_leases
        (workspace_id,namespace_id,proxy_id,operation_id,generation,worker_id,fencing_token,expires_at_micros)
        VALUES ($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT (workspace_id,namespace_id,proxy_id)
        DO UPDATE SET operation_id = $4, generation = $5, worker_id = $6,
        fencing_token = mcp_proxy_controller_leases.fencing_token + 1, expires_at_micros = $7
        WHERE mcp_proxy_controller_leases.workspace_id = $1
        AND mcp_proxy_controller_leases.namespace_id = $2 AND mcp_proxy_controller_leases.proxy_id = $3
        AND (mcp_proxy_controller_leases.expires_at_micros <= $8
             OR mcp_proxy_controller_leases.generation < $5) RETURNING fencing_token",
        &[&target.scope.workspace_id, &target.scope.namespace_id, target.proxy_id.as_uuid(),
          &operation_id, &generation, &worker, &expires, &now]).map_err(db_error)?
        else { return Ok(None); };
    let fencing_token = u64::try_from(lease.get::<_, i64>(0)).map_err(|_| configuration_error())?;
    tx.commit().map_err(db_error)?;
    Ok(Some(LeasedOperation {
        operation,
        worker_id: worker.to_owned(),
        fencing_token,
        lease_expires_at_micros: u64::try_from(expires).map_err(|_| configuration_error())?,
    }))
}
