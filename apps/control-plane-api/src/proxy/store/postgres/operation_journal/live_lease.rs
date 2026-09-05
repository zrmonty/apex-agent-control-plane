//! One exact live-lease predicate shared by observations and snapshot reads.

use super::{Target, Transaction, db_error};
use crate::proxy::ProxyError;
use apex_durability::PostgresClientOps;
use uuid::Uuid;

/// Caller already holds the exact proxy row lock. This locks the matching lease
/// and returns its stored expiry without renewing it or changing the fence.
/// Deliberately no terminal-state check: observations retain exact-event retries.
pub(in super::super) fn exact_live_lease_expiry(
    tx: &mut Transaction<'_>,
    target: Target<'_>,
    operation_id: &Uuid,
    generation: i64,
    worker_id: &str,
    fence: i64,
    now: i64,
) -> Result<Option<i64>, ProxyError> {
    tx.query_opt(
        "SELECT expires_at_micros FROM mcp_proxy_controller_leases WHERE workspace_id = $1
        AND namespace_id = $2 AND proxy_id = $3 AND operation_id = $4 AND generation = $5
        AND worker_id = $6 AND fencing_token = $7 AND expires_at_micros > $8 FOR UPDATE",
        &[
            &target.scope.workspace_id,
            &target.scope.namespace_id,
            target.proxy_id.as_uuid(),
            operation_id,
            &generation,
            &worker_id,
            &fence,
            &now,
        ],
    )
    .map_err(db_error)?
    .map(|row| row.try_get(0).map_err(|_| super::configuration_error()))
    .transpose()
}
