//! PostgreSQL-backed durable outbox (multi-process authority).

use std::str::FromStr;

use postgres::{Client, NoTls};
use prost::Message;
use uuid::Uuid;

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{
    GatewayError, GatewayErrorCode, IngestRequest, is_lowercase_uuidv7, is_scope_identifier, proto,
};

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
        let mut client = Client::connect(connection_string, NoTls)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        client
            .batch_execute(include_str!("../../../../deploy/postgres/outbox.sql"))
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
                "complete" => EnqueueResult::AlreadyComplete,
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
        tx.execute(
            "INSERT INTO apex_event_outbox
             (workspace_id, namespace_id, event_id, envelope, payload_hash, state)
             VALUES ($1, $2, $3, $4, $5, 'pending')",
            &[
                &event.workspace_id,
                &event.namespace_id,
                &event_uuid,
                &event.envelope.as_slice(),
                &payload_hash.as_slice(),
            ],
        )
        .map_err(|_| GatewayError::internal())?;
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

    fn pending(&mut self) -> Vec<IngestRequest> {
        let rows = match self.client.query(
            "SELECT workspace_id, namespace_id, event_id, envelope
             FROM apex_event_outbox
             WHERE state = 'pending'
             ORDER BY created_at ASC
             LIMIT 10000",
            &[],
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
