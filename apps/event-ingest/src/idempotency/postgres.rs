//! PostgreSQL-backed idempotency store (multi-process authority).

use std::collections::HashMap;
use std::str::FromStr;

use postgres::Client;
use uuid::Uuid;

use super::types::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult, scope_capacity,
};
use crate::{GatewayError, GatewayErrorCode, is_lowercase_uuidv7, is_scope_identifier};

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
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if connection_string.is_empty() || connection_string.len() > 2048 {
            return Err(GatewayError::invalid_idempotency_configuration());
        }
        let mut client = crate::postgres_transport::connect(connection_string)
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        client
            .batch_execute(include_str!("../../../../deploy/postgres/idempotency.sql"))
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
        self.next_token += 1;
        tx.execute(
            "INSERT INTO apex_ingest_idempotency
             (workspace_id, namespace_id, event_id, payload_hash, state, reservation_id)
             VALUES ($1, $2, $3, $4, 'pending', $5)",
            &[
                &key.workspace_id,
                &key.namespace_id,
                &event_uuid,
                &payload_hash.as_slice(),
                &reservation_id,
            ],
        )
        .map_err(|_| GatewayError::internal())?;
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
