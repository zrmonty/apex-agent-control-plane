//! PostgreSQL-backed idempotency store (multi-process authority).

use std::collections::HashMap;
use std::str::FromStr;

use crate::{PostgresClientOps, PostgresConnection as Client};
use uuid::Uuid;

use super::types::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult, scope_capacity,
};
use crate::{GatewayError, GatewayErrorCode, is_lowercase_uuidv7, is_scope_identifier};

/// Advisory-lock key serialising this schema's `IF NOT EXISTS` DDL across
/// replicas. Distinct from the outbox's key so the two schemas do not block
/// each other.
const IDEMPOTENCY_SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0001_u64 as i64;

/// Authoritative idempotency journal backed by `deploy/postgres/idempotency.sql`.
///
/// The database holds key/hash/`reservation_id` state across processes. The
/// in-process `token → reservation_id` map is a local handle only (same pattern
/// as the file journal).
pub struct PostgresIdempotencyStore {
    client: Client,
    capacity: usize,
    tokens: HashMap<u64, Uuid>,
    next_token: u64,
}

impl PostgresIdempotencyStore {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, GatewayError> {
        Self::connect_using(connection_string, capacity, |url| {
            crate::connect_postgres(url).map(Client::Standard)
        })
    }

    /// Same authoritative store with deadline-bound operations on its owned
    /// connection. Construct, use and drop outside an async runtime context.
    pub fn connect_for_worker(
        connection_string: &str,
        capacity: usize,
    ) -> Result<Self, GatewayError> {
        Self::connect_using(
            connection_string,
            capacity,
            crate::connect_postgres_for_worker,
        )
    }

    fn connect_using(
        connection_string: &str,
        capacity: usize,
        connect: fn(&str) -> Result<Client, ()>,
    ) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if connection_string.is_empty() || connection_string.len() > 2048 {
            return Err(GatewayError::invalid_idempotency_configuration());
        }
        let mut client = connect(connection_string)
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        crate::postgres_transport::apply_postgres_schema(
            &mut client,
            IDEMPOTENCY_SCHEMA_LOCK,
            include_str!("../../../../deploy/postgres/idempotency.sql"),
        )
        .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        Ok(Self {
            client,
            capacity,
            tokens: HashMap::new(),
            next_token: 1,
        })
    }
}

impl IdempotencyStore for PostgresIdempotencyStore {
    fn check_admission_readiness(
        &mut self,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<(), GatewayError> {
        crate::postgres_readiness::check(
            &mut self.client,
            crate::postgres_readiness::Store::Idempotency {
                scope_capacity: scope_capacity(self.capacity),
                next_token: self.next_token,
            },
            self.capacity,
            workspace_id,
            namespace_id,
        )
    }

    fn reserve(
        &mut self,
        key: IdempotencyKey,
        payload_hash: [u8; 32],
    ) -> Result<ReservationResult, GatewayError> {
        if !is_scope_identifier(&key.workspace_id)
            || !is_scope_identifier(&key.namespace_id)
            || !is_lowercase_uuidv7(&key.event_id)
        {
            return Err(GatewayError::invalid_idempotency_configuration());
        }
        let event_uuid = Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?;
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| GatewayError::internal())?;

        let existing = tx
            .query_opt(
                "SELECT payload_hash, state FROM apex_ingest_idempotency
                 WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3
                 FOR UPDATE",
                &[&key.workspace_id, &key.namespace_id, &event_uuid],
            )
            .map_err(|_| GatewayError::internal())?;
        if let Some(row) = existing {
            let hash: Vec<u8> = row.get(0);
            let state: String = row.get(1);
            let same = hash.as_slice() == payload_hash.as_slice();
            return Ok(match (state.as_str(), same) {
                ("committed", true) => ReservationResult::Duplicate,
                ("committed", false) => ReservationResult::Conflict,
                ("pending", true) => ReservationResult::InProgress,
                ("pending", false) => ReservationResult::Conflict,
                _ => return Err(GatewayError::internal()),
            });
        }

        let scope_count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM apex_ingest_idempotency
                 WHERE workspace_id = $1 AND namespace_id = $2",
                &[&key.workspace_id, &key.namespace_id],
            )
            .map_err(|_| GatewayError::internal())?
            .get(0);
        let total: i64 = tx
            .query_one("SELECT COUNT(*) FROM apex_ingest_idempotency", &[])
            .map_err(|_| GatewayError::internal())?
            .get(0);
        if scope_count as usize >= scope_capacity(self.capacity) || total as usize >= self.capacity
        {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if self.next_token == u64::MAX {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        let reservation_id = Uuid::new_v4();
        let token = self.next_token;

        // `SELECT ... FOR UPDATE` above locks nothing when the row is absent --
        // there is no row yet to lock. Concurrent replicas therefore all read
        // "absent" and all reach this insert, and only the primary key
        // arbitrates. A plain INSERT makes every loser a unique-violation,
        // which this layer can only report as INTERNAL_FAILURE: a code that
        // carries no retry guidance and reads to a client as a server defect
        // rather than as contention on a key someone else owns.
        //
        // ON CONFLICT DO NOTHING turns the race into a value: zero rows means
        // another replica won, and the winner's row then answers the question
        // truthfully. This is the protocol deploy/postgres/idempotency.sql has
        // always specified ("INSERT ... ON CONFLICT (workspace_id,
        // namespace_id, event_id)"); the code simply did not implement it.
        let inserted = tx
            .execute(
                "INSERT INTO apex_ingest_idempotency
                 (workspace_id, namespace_id, event_id, payload_hash, state, reservation_id)
                 VALUES ($1, $2, $3, $4, 'pending', $5)
                 ON CONFLICT (workspace_id, namespace_id, event_id) DO NOTHING",
                &[
                    &key.workspace_id,
                    &key.namespace_id,
                    &event_uuid,
                    &payload_hash.as_slice(),
                    &reservation_id,
                ],
            )
            .map_err(|_| GatewayError::internal())?;
        if inserted == 0 {
            // The winner's row is committed by the time our conflicting insert
            // returns, so this read sees the authoritative state.
            let row = tx
                .query_opt(
                    "SELECT payload_hash, state FROM apex_ingest_idempotency
                     WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3",
                    &[&key.workspace_id, &key.namespace_id, &event_uuid],
                )
                .map_err(|_| GatewayError::internal())?
                .ok_or_else(GatewayError::internal)?;
            let hash: Vec<u8> = row.get(0);
            let state: String = row.get(1);
            let same = hash.as_slice() == payload_hash.as_slice();
            tx.commit().map_err(|_| GatewayError::internal())?;
            return Ok(match (state.as_str(), same) {
                ("committed", true) => ReservationResult::Duplicate,
                ("committed", false) => ReservationResult::Conflict,
                ("pending", true) => ReservationResult::InProgress,
                ("pending", false) => ReservationResult::Conflict,
                _ => return Err(GatewayError::internal()),
            });
        }
        self.next_token += 1;
        tx.commit().map_err(|_| GatewayError::internal())?;
        self.tokens.insert(token, reservation_id);
        Ok(ReservationResult::Reserved(IdempotencyReservation {
            token,
        }))
    }

    fn commit(&mut self, reservation: IdempotencyReservation) -> Result<(), GatewayError> {
        let Some(reservation_id) = self.tokens.remove(&reservation.token) else {
            return Err(GatewayError::internal());
        };
        let updated = self
            .client
            .execute(
                "UPDATE apex_ingest_idempotency
                 SET state = 'committed', committed_at = now()
                 WHERE reservation_id = $1 AND state = 'pending'",
                &[&reservation_id],
            )
            .map_err(|_| GatewayError::internal())?;
        if updated != 1 {
            return Err(GatewayError::internal());
        }
        Ok(())
    }

    fn abort(&mut self, reservation: IdempotencyReservation) {
        if let Some(reservation_id) = self.tokens.remove(&reservation.token) {
            let _ = self.client.execute(
                "DELETE FROM apex_ingest_idempotency
                 WHERE reservation_id = $1 AND state = 'pending'",
                &[&reservation_id],
            );
        }
    }

    fn maintain(&mut self, _now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        // PostgreSQL's clock is authoritative for rows written by every
        // replica. The caller's wall clock is intentionally not used here.
        self.client
            .execute(
                "DELETE FROM apex_ingest_idempotency
                 WHERE state = 'committed'
                   AND committed_at < now() - make_interval(secs => $1)",
                &[&(retention_millis as f64 / 1000.0)],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(())
    }
}

impl PostgresIdempotencyStore {
    /// Deletes `pending` reservations older than `max_age` (never touches
    /// `committed` rows, per the schema's reaper contract in
    /// `deploy/postgres/idempotency.sql`). A pending row can only survive
    /// past its writer's fanout window if that process crashed between
    /// `reserve()` committing the row and `commit()`/`abort()` ever running —
    /// the `reservation_id -> token` mapping that would release it lives only
    /// in that process's memory, so nothing else can free the key without
    /// this reaper. `max_age` should comfortably exceed the slowest realistic
    /// fanout (retries + timeouts), not just typical latency, so a live,
    /// still-in-flight reservation is never reclaimed out from under it.
    pub fn reap_expired(&mut self, max_age: std::time::Duration) -> Result<u64, GatewayError> {
        let deleted = self
            .client
            .execute(
                "DELETE FROM apex_ingest_idempotency
                 WHERE state = 'pending'
                   AND created_at < now() - make_interval(secs => $1)",
                &[&max_age.as_secs_f64()],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod readiness_token_tests {
    use super::*;

    #[test]
    fn postgres_readiness_rejects_invalid_tokens_without_consuming_handles() {
        if std::env::var("APEX_PG_READINESS_FIXTURE").ok().as_deref() != Some("1") {
            eprintln!("SKIP: requires explicit isolated APEX_PG_READINESS_FIXTURE");
            return;
        }
        let url =
            std::env::var("APEX_PG_READINESS_FIXTURE_URL").expect("explicit fixture requires URL");
        let client =
            crate::connect_postgres_for_worker(&url).expect("explicit fixture must be reachable");
        // No schema or test-only production seam: invalid local state must be
        // rejected before SQL, even on a freshly connected empty database.
        let reservation_id = Uuid::new_v4();
        let mut store = PostgresIdempotencyStore {
            client,
            capacity: 64,
            tokens: HashMap::from([(1, reservation_id)]),
            next_token: 0,
        };
        for token in [0, u64::MAX] {
            store.next_token = token;
            assert_eq!(
                store
                    .check_admission_readiness("ws", "ns")
                    .unwrap_err()
                    .code,
                GatewayErrorCode::IdempotencyCapacity
            );
            assert_eq!(store.next_token, token);
            assert_eq!(store.tokens, HashMap::from([(1, reservation_id)]));
        }
    }
}
