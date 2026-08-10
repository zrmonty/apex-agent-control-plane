//! PostgreSQL-backed durable outbox (multi-process authority).

use std::str::FromStr;
use std::time::Duration;

use postgres::Client;
use uuid::Uuid;

use super::postgres_replay::PostgresReplayOps;
use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{
    GatewayError, GatewayErrorCode, IngestRequest, is_lowercase_uuidv7, is_scope_identifier,
};

/// Advisory-lock key serialising this schema's `IF NOT EXISTS` DDL across
/// replicas. Distinct from the idempotency schema's key so the two do not
/// block each other.
const OUTBOX_SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0002_u64 as i64;

/// How long a claimed pending row stays invisible to other replay workers.
///
/// Must exceed the slowest realistic fanout -- the bounded retry ladder plus
/// every sink's timeout -- so an in-flight replay is never re-claimed while it
/// is still running. Too short duplicates work; too long only delays recovery
/// after a claimer dies, which the startup replay and the next cycle absorb.
pub(super) const OUTBOX_CLAIM_LEASE_SECONDS: f64 = 120.0;

/// Authoritative outbox backed by `deploy/postgres/outbox.sql`.
pub struct PostgresOutbox {
    pub(super) client: Client,
    pub(super) capacity: usize,
}

impl PostgresOutbox {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if connection_string.is_empty() || connection_string.len() > 2048 {
            return Err(GatewayError::invalid_outbox_configuration());
        }
        let mut client = crate::postgres_transport::connect_postgres(connection_string)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        crate::postgres_transport::apply_postgres_schema(
            &mut client,
            OUTBOX_SCHEMA_LOCK,
            include_str!("../../../../deploy/postgres/outbox.sql"),
        )
        .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        Ok(Self { client, capacity })
    }
}

impl EventOutbox for PostgresOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        if !is_scope_identifier(&event.workspace_id)
            || !is_scope_identifier(&event.namespace_id)
            || !is_lowercase_uuidv7(&event.event_id)
        {
            return Err(GatewayError::invalid_outbox_configuration());
        }
        if event.envelope.is_empty() || event.envelope.len() > crate::MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
        }
        let event_uuid = Uuid::from_str(&event.event_id).map_err(|_| GatewayError::internal())?;
        let payload_hash = {
            use sha2::{Digest, Sha256};
            let digest: [u8; 32] = Sha256::digest(&event.envelope).into();
            digest
        };
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| GatewayError::internal())?;
        let existing = tx
            .query_opt(
                "SELECT state, envelope FROM apex_event_outbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3
                 FOR UPDATE",
                &[&event.workspace_id, &event.namespace_id, &event_uuid],
            )
            .map_err(|_| GatewayError::internal())?;
        if let Some(row) = existing {
            let state: String = row.get(0);
            let envelope: Vec<u8> = row.get(1);
            return Ok(match state.as_str() {
                // A completed row must be matched on content, not just on the
                // key. Answering AlreadyComplete for any payload would
                // acknowledge an event that was never stored, and would lose
                // the idempotency-conflict signal for a reused event_id.
                "complete" if envelope == event.envelope => EnqueueResult::AlreadyComplete,
                "complete" => return Err(GatewayError::idempotency_conflict()),
                "pending" if envelope == event.envelope => EnqueueResult::AlreadyPending,
                "pending" => return Err(GatewayError::idempotency_conflict()),
                _ => return Err(GatewayError::internal()),
            });
        }
        let total: i64 = tx
            .query_one("SELECT COUNT(*) FROM apex_event_outbox", &[])
            .map_err(|_| GatewayError::internal())?
            .get(0);
        if total as usize >= self.capacity {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        // `SELECT ... FOR UPDATE` above locks nothing when the row is absent,
        // so concurrent replicas all read "absent" and all reach this insert.
        // A plain INSERT makes every loser a unique-violation reported as
        // INTERNAL_FAILURE instead of the AlreadyPending / AlreadyComplete /
        // conflict answer the row actually supports. See the matching comment
        // in idempotency/postgres.rs.
        let inserted = tx
            .execute(
                "INSERT INTO apex_event_outbox
                 (workspace_id, namespace_id, event_id, envelope, payload_hash, state)
                 VALUES ($1, $2, $3, $4, $5, 'pending')
                 ON CONFLICT (workspace_id, namespace_id, event_id) DO NOTHING",
                &[
                    &event.workspace_id,
                    &event.namespace_id,
                    &event_uuid,
                    &event.envelope.as_slice(),
                    &payload_hash.as_slice(),
                ],
            )
            .map_err(|_| GatewayError::internal())?;
        if inserted == 0 {
            let row = tx
                .query_opt(
                    "SELECT state, envelope FROM apex_event_outbox
                     WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3",
                    &[&event.workspace_id, &event.namespace_id, &event_uuid],
                )
                .map_err(|_| GatewayError::internal())?
                .ok_or_else(GatewayError::internal)?;
            let state: String = row.get(0);
            let envelope: Vec<u8> = row.get(1);
            tx.commit().map_err(|_| GatewayError::internal())?;
            return match state.as_str() {
                "complete" if envelope == event.envelope => Ok(EnqueueResult::AlreadyComplete),
                "complete" => Err(GatewayError::idempotency_conflict()),
                "pending" if envelope == event.envelope => Ok(EnqueueResult::AlreadyPending),
                "pending" => Err(GatewayError::idempotency_conflict()),
                _ => Err(GatewayError::internal()),
            };
        }
        tx.commit().map_err(|_| GatewayError::internal())?;
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        if !is_scope_identifier(&key.workspace_id)
            || !is_scope_identifier(&key.namespace_id)
            || !is_lowercase_uuidv7(&key.event_id)
        {
            return Err(GatewayError::invalid_outbox_configuration());
        }
        let event_uuid = Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?;
        let updated = self
            .client
            .execute(
                "UPDATE apex_event_outbox
                 SET state = 'complete', completed_at = now()
                 WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3
                   AND state = 'pending' AND quarantined_at IS NULL",
                &[&key.workspace_id, &key.namespace_id, &event_uuid],
            )
            .map_err(|_| GatewayError::internal())?;
        if updated == 0 {
            // Already complete is a no-op success; missing row is internal.
            let exists: bool = self
                .client
                .query_opt(
                    "SELECT 1 FROM apex_event_outbox
                     WHERE workspace_id = $1 AND namespace_id = $2 AND event_id = $3",
                    &[&key.workspace_id, &key.namespace_id, &event_uuid],
                )
                .map_err(|_| GatewayError::internal())?
                .is_some();
            if !exists {
                return Err(GatewayError::internal());
            }
        }
        Ok(())
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut workspaces = Vec::with_capacity(keys.len());
        let mut namespaces = Vec::with_capacity(keys.len());
        let mut event_ids = Vec::with_capacity(keys.len());
        for key in keys {
            if !is_scope_identifier(&key.workspace_id)
                || !is_scope_identifier(&key.namespace_id)
                || !is_lowercase_uuidv7(&key.event_id)
            {
                return Err(GatewayError::invalid_outbox_configuration());
            }
            workspaces.push(key.workspace_id.clone());
            namespaces.push(key.namespace_id.clone());
            event_ids.push(Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?);
        }

        let mut tx = self
            .client
            .transaction()
            .map_err(|_| GatewayError::internal())?;
        let updated = tx
            .execute(
                "UPDATE apex_event_outbox
                 SET state = 'complete', completed_at = now()
                 WHERE (workspace_id, namespace_id, event_id) IN
                       (SELECT * FROM unnest($1::text[], $2::text[], $3::uuid[]))
                   AND state = 'pending' AND quarantined_at IS NULL",
                &[&workspaces, &namespaces, &event_ids],
            )
            .map_err(|_| GatewayError::internal())?;
        if updated < keys.len() as u64 {
            let existing: i64 = tx
                .query_one(
                    "SELECT COUNT(*)
                    FROM apex_event_outbox
                    WHERE (workspace_id, namespace_id, event_id) IN
                           (SELECT * FROM unnest($1::text[], $2::text[], $3::uuid[]))",
                    &[&workspaces, &namespaces, &event_ids],
                )
                .map_err(|_| GatewayError::internal())?
                .get(0);
            if existing != keys.len() as i64 {
                return Err(GatewayError::internal());
            }
        }
        tx.commit().map_err(|_| GatewayError::internal())?;
        Ok(())
    }

    fn reschedule(&mut self, keys: &[OutboxKey], after: Duration) -> Result<(), GatewayError> {
        PostgresReplayOps::reschedule(self, keys, after)
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        PostgresReplayOps::maintain(self, now_millis, retention_millis)
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        PostgresReplayOps::pending(self)
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        PostgresReplayOps::pending_batch(self, limit)
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        PostgresReplayOps::pending_count(self)
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        PostgresReplayOps::recent_completed_batch(self, since_millis, limit)
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        PostgresReplayOps::pending_reconciliation_batch(self, limit)
    }

    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError> {
        PostgresReplayOps::quarantine(self, keys, reason)
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        PostgresReplayOps::quarantined_batch(self, limit)
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        PostgresReplayOps::quarantined_count(self)
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        PostgresReplayOps::requeue_quarantined(self, keys)
    }
}
