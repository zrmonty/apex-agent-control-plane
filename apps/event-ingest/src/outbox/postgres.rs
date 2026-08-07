//! PostgreSQL-backed durable outbox (multi-process authority).

use std::str::FromStr;

use postgres::Client;
use prost::Message;
use uuid::Uuid;

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{
    GatewayError, GatewayErrorCode, IngestRequest, is_lowercase_uuidv7, is_scope_identifier, proto,
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
const OUTBOX_CLAIM_LEASE_SECONDS: f64 = 120.0;

/// Authoritative outbox backed by `deploy/postgres/outbox.sql`.
pub struct PostgresOutbox {
    client: Client,
    capacity: usize,
}

impl PostgresOutbox {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if connection_string.is_empty() || connection_string.len() > 2048 {
            return Err(GatewayError::invalid_outbox_configuration());
        }
        let mut client = crate::postgres_transport::connect(connection_string)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        crate::postgres_transport::apply_schema(
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
                   AND state = 'pending'",
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

    /// Claims pending rows with a lease instead of merely listing them.
    ///
    /// The previous implementation was a bare `SELECT ... WHERE state =
    /// 'pending'`, so every replica's replay worker read the same rows every
    /// cycle and every replica fanned each one out. `deploy/postgres/outbox.sql`
    /// has always specified a claim -- "Workers claim pending rows with
    /// SELECT ... FOR UPDATE SKIP LOCKED" -- and the `attempts` /
    /// `next_attempt_at` columns exist for exactly this, but nothing read or
    /// wrote them.
    ///
    /// Correctness did not visibly break only because every sink happens to be
    /// idempotent on `event_id` today. Resting multi-replica exactly-once on
    /// that property holding forever, in every sink anyone ever adds, is not a
    /// guarantee the outbox should be delegating.
    ///
    /// A single `UPDATE ... RETURNING` is the claim: row locks make it atomic,
    /// `SKIP LOCKED` lets concurrent workers take disjoint batches, and the
    /// lease is what returns a row to the pool if the claimer dies. The lease
    /// must comfortably exceed the slowest fanout (the bounded retry ladder
    /// plus sink timeouts) so a live, in-flight replay is never re-claimed out
    /// from under itself.
    fn pending(&mut self) -> Vec<IngestRequest> {
        let rows = match self.client.query(
            "UPDATE apex_event_outbox AS o
             SET attempts = o.attempts + 1,
                 next_attempt_at = now() + make_interval(secs => $1)
             WHERE (o.workspace_id, o.namespace_id, o.event_id) IN (
                 SELECT c.workspace_id, c.namespace_id, c.event_id
                 FROM apex_event_outbox AS c
                 WHERE c.state = 'pending' AND c.next_attempt_at <= now()
                 ORDER BY c.created_at ASC
                 LIMIT 10000
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING o.workspace_id, o.namespace_id, o.event_id, o.envelope",
            &[&OUTBOX_CLAIM_LEASE_SECONDS],
        ) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id: String = row.get(0);
            let namespace_id: String = row.get(1);
            let _event_id: Uuid = row.get(2);
            let envelope: Vec<u8> = row.get(3);
            let Ok(decoded) = proto::EventEnvelope::decode(envelope.as_slice()) else {
                continue;
            };
            // Rows are untrusted durable state. Re-run the same envelope
            // validation used at admission instead of constructing an
            // unchecked request from database columns.
            let Ok(event) = IngestRequest::from_validated_transport(decoded) else {
                continue;
            };
            if event.scope_key() != format!("{workspace_id}/{namespace_id}") {
                continue;
            }
            events.push(event);
        }
        events
    }
}
