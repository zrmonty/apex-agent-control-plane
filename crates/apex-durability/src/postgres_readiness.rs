//! Non-admitting observations on the actual store's deadline-bound connection.
//! One SELECT gives catalog checks and exact global/scoped counts one statement
//! snapshot and one five-second worker deadline (including wire/prepare waits).
//! No transaction/reservation/claim/DDL is issued. Success cannot promise a
//! future commit, disk allocation, or downstream delivery. Legacy unbounded
//! connections remain usable for their existing APIs but readiness fails closed.

use crate::{GatewayError, GatewayErrorCode, PostgresConnection, is_scope_identifier};

pub(crate) enum Store {
    Idempotency {
        scope_capacity: usize,
        next_token: u64,
    },
    Outbox,
}

pub(crate) fn check(
    connection: &mut PostgresConnection,
    store: Store,
    capacity: usize,
    workspace_id: &str,
    namespace_id: &str,
) -> Result<(), GatewayError> {
    if !is_scope_identifier(workspace_id) || !is_scope_identifier(namespace_id) {
        return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
    }
    let (table, scope_limit) = match store {
        Store::Idempotency {
            scope_capacity,
            next_token,
        } => {
            if next_token == 0 || next_token == u64::MAX {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
            }
            ("apex_ingest_idempotency", Some(scope_capacity))
        }
        Store::Outbox => ("apex_event_outbox", None),
    };
    // A server statement timeout cannot bound a blackholed socket. Never
    // silently run readiness on a legacy synchronous connection or open a
    // separate probe connection that would observe a different session/role.
    let PostgresConnection::Worker(client) = connection else {
        return Err(GatewayError::internal());
    };
    // `table` comes only from the closed enum above, never from caller input.
    // Check each privilege separately: a comma-separated privilege list means
    // ANY privilege in PostgreSQL, not ALL. Requiring table-level DML grants is
    // deliberately conservative for column-only grants. RLS must be inactive
    // for this effective role, even when a policy appears to expose all rows.
    // The guarded scalar subquery must not scan an unusable relation: a view
    // or an RLS policy could call volatile functions with write side effects.
    let sql = format!(
        "WITH capability AS MATERIALIZED (SELECT
           NOT pg_catalog.pg_is_in_recovery()
           AND pg_catalog.current_setting('transaction_read_only') = 'off'
           AND pg_catalog.current_setting('default_transaction_read_only') = 'off'
           AND c.relpersistence = 'p' AND c.relkind = 'r'
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits WHERE inhparent = c.oid)
           AND pg_catalog.has_schema_privilege(c.relnamespace, 'USAGE')
           AND pg_catalog.has_table_privilege(c.oid, 'SELECT')
           AND pg_catalog.has_table_privilege(c.oid, 'INSERT')
           AND pg_catalog.has_table_privilege(c.oid, 'UPDATE')
           AND pg_catalog.has_table_privilege(c.oid, 'DELETE')
           AND NOT pg_catalog.row_security_active(c.oid) AS usable
         FROM pg_catalog.pg_class c
         WHERE c.oid = '{table}'::regclass)
         SELECT usable, CASE WHEN usable THEN (
           SELECT ARRAY[count(*),
             count(*) FILTER (WHERE workspace_id = $1 AND namespace_id = $2)]
           FROM {table}
         ) END FROM capability"
    );
    let row = client
        .query_one(&sql, &[&workspace_id, &namespace_id])
        .map_err(|_| GatewayError::internal())?;
    let usable: bool = row.try_get(0).map_err(|_| GatewayError::internal())?;
    if !usable {
        return Err(GatewayError::internal());
    }
    let counts: Vec<i64> = row.try_get(1).map_err(|_| GatewayError::internal())?;
    let [total, scoped] = counts.as_slice() else {
        return Err(GatewayError::internal());
    };
    let total = usize::try_from(*total).map_err(|_| GatewayError::internal())?;
    let scoped = usize::try_from(*scoped).map_err(|_| GatewayError::internal())?;
    if total >= capacity || scope_limit.is_some_and(|limit| scoped >= limit) {
        return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
    }
    Ok(())
}
