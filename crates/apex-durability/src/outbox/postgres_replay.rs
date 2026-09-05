use super::postgres::{OUTBOX_CLAIM_LEASE_SECONDS, PostgresOutbox};
use super::types::OutboxKey;
use crate::{GatewayError, IngestRequest, PostgresClientOps, proto};
use prost::Message;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

pub(super) trait PostgresReplayOps {
    fn reschedule(&mut self, keys: &[OutboxKey], after: Duration) -> Result<(), GatewayError>;
    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError>;
    fn pending(&mut self) -> Vec<IngestRequest>;
    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError>;
    fn pending_count(&mut self) -> Result<u64, GatewayError>;
    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError>;
    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError>;
    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError>;
    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError>;
    fn quarantined_count(&mut self) -> Result<u64, GatewayError>;
    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError>;
    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError>;
}

impl PostgresReplayOps for PostgresOutbox {
    fn reschedule(&mut self, keys: &[OutboxKey], after: Duration) -> Result<(), GatewayError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut workspaces = Vec::with_capacity(keys.len());
        let mut namespaces = Vec::with_capacity(keys.len());
        let mut event_ids = Vec::with_capacity(keys.len());
        for key in keys {
            workspaces.push(key.workspace_id.clone());
            namespaces.push(key.namespace_id.clone());
            event_ids.push(Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?);
        }
        let seconds = after.as_secs_f64();
        self.client
            .execute(
                "UPDATE apex_event_outbox
                 SET next_attempt_at = now() + make_interval(secs => $1)
                 WHERE state = 'pending'
                   AND quarantined_at IS NULL
                   AND attempts < 8
                   AND (workspace_id, namespace_id, event_id) IN
                       (SELECT * FROM unnest($2::text[], $3::text[], $4::uuid[]))",
                &[&seconds, &workspaces, &namespaces, &event_ids],
            )
            .map_err(|_| GatewayError::internal())?;
        self.client
            .execute(
                "UPDATE apex_event_outbox
                 SET quarantined_at = now(), quarantine_reason = 'replay_attempts_exhausted'
                 WHERE state = 'pending'
                   AND quarantined_at IS NULL
                   AND attempts >= 8
                   AND (workspace_id, namespace_id, event_id) IN
                       (SELECT * FROM unnest($1::text[], $2::text[], $3::uuid[]))",
                &[&workspaces, &namespaces, &event_ids],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(())
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        let now_millis = i64::try_from(now_millis).map_err(|_| GatewayError::internal())?;
        let retention_millis =
            i64::try_from(retention_millis).map_err(|_| GatewayError::internal())?;
        self.client
            .execute(
                "DELETE FROM apex_event_outbox
                 WHERE state = 'complete'
                   AND completed_at <= to_timestamp($1::double precision / 1000.0)
                                      - make_interval(secs => ($2::double precision / 1000.0))",
                &[&now_millis, &retention_millis],
            )
            .map_err(|_| GatewayError::internal())?;
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
        self.pending_batch(10_000).unwrap_or_default()
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let rows = self
            .client
            .query(
                "UPDATE apex_event_outbox AS o
             SET attempts = o.attempts + 1,
                 next_attempt_at = now() + make_interval(secs => $1)
             WHERE (o.workspace_id, o.namespace_id, o.event_id) IN (
                 SELECT c.workspace_id, c.namespace_id, c.event_id
                 FROM apex_event_outbox AS c
                 WHERE c.state = 'pending'
                   AND c.quarantined_at IS NULL
                   AND c.next_attempt_at <= now()
                 ORDER BY c.created_at ASC
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING o.workspace_id, o.namespace_id, o.event_id, o.envelope",
                &[&OUTBOX_CLAIM_LEASE_SECONDS, &limit],
            )
            .map_err(|_| GatewayError::internal())?;
        let mut events = Vec::with_capacity(rows.len());
        let mut poison = Vec::new();
        for row in rows {
            let workspace_id: String = row.get(0);
            let namespace_id: String = row.get(1);
            let event_id: Uuid = row.get(2);
            let envelope: Vec<u8> = row.get(3);
            let Ok(decoded) = proto::EventEnvelope::decode(envelope.as_slice()) else {
                poison.push(OutboxKey {
                    workspace_id,
                    namespace_id,
                    event_id: event_id.to_string(),
                });
                continue;
            };
            // Rows are untrusted durable state. Re-run the same envelope
            // validation used at admission instead of constructing an
            // unchecked request from database columns.
            let Ok(event) = IngestRequest::from_validated_transport(decoded) else {
                poison.push(OutboxKey {
                    workspace_id,
                    namespace_id,
                    event_id: event_id.to_string(),
                });
                continue;
            };
            if event.scope_key() != format!("{workspace_id}/{namespace_id}") {
                poison.push(OutboxKey {
                    workspace_id,
                    namespace_id,
                    event_id: event_id.to_string(),
                });
                continue;
            }
            events.push(event);
        }
        if !poison.is_empty() {
            self.quarantine(&poison, "malformed_durable_event")?;
        }
        Ok(events)
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        let count: i64 = self
            .client
            .query_one(
                "SELECT COUNT(*) FROM apex_event_outbox
                 WHERE state = 'pending' AND quarantined_at IS NULL",
                &[],
            )
            .map_err(|_| GatewayError::internal())?
            .get(0);
        count.try_into().map_err(|_| GatewayError::internal())
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        let since_millis = i64::try_from(since_millis).map_err(|_| GatewayError::internal())?;
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let rows = self
            .client
            .query(
                "SELECT workspace_id, namespace_id, event_id, envelope
                 FROM apex_event_outbox
                 WHERE state = 'complete'
                   AND completed_at >= to_timestamp($1::double precision / 1000.0)
                 ORDER BY completed_at ASC
                 LIMIT $2",
                &[&since_millis, &limit],
            )
            .map_err(|_| GatewayError::internal())?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id: String = row.get(0);
            let namespace_id: String = row.get(1);
            let envelope: Vec<u8> = row.get(3);
            let decoded = proto::EventEnvelope::decode(envelope.as_slice())
                .map_err(|_| GatewayError::internal())?;
            let event = IngestRequest::from_validated_transport(decoded)
                .map_err(|_| GatewayError::internal())?;
            if event.scope_key() != format!("{workspace_id}/{namespace_id}") {
                return Err(GatewayError::internal());
            }
            events.push(event);
        }
        Ok(events)
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let rows = self
            .client
            .query(
                "SELECT workspace_id, namespace_id, event_id, envelope
                 FROM apex_event_outbox
                 WHERE state = 'pending' AND quarantined_at IS NULL
                 ORDER BY created_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .map_err(|_| GatewayError::internal())?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id: String = row.get(0);
            let namespace_id: String = row.get(1);
            let envelope: Vec<u8> = row.get(3);
            let decoded = proto::EventEnvelope::decode(envelope.as_slice())
                .map_err(|_| GatewayError::internal())?;
            let event = IngestRequest::from_validated_transport(decoded)
                .map_err(|_| GatewayError::internal())?;
            if event.scope_key() != format!("{workspace_id}/{namespace_id}") {
                return Err(GatewayError::internal());
            }
            events.push(event);
        }
        Ok(events)
    }

    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut workspaces = Vec::with_capacity(keys.len());
        let mut namespaces = Vec::with_capacity(keys.len());
        let mut event_ids = Vec::with_capacity(keys.len());
        for key in keys {
            workspaces.push(key.workspace_id.clone());
            namespaces.push(key.namespace_id.clone());
            event_ids.push(Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?);
        }
        self.client
            .execute(
                "UPDATE apex_event_outbox
                 SET quarantined_at = now(), quarantine_reason = $1
                 WHERE state = 'pending'
                   AND quarantined_at IS NULL
                   AND (workspace_id, namespace_id, event_id) IN
                       (SELECT * FROM unnest($2::text[], $3::text[], $4::uuid[]))",
                &[&reason, &workspaces, &namespaces, &event_ids],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(())
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let rows = self
            .client
            .query(
                "SELECT workspace_id, namespace_id, event_id
                 FROM apex_event_outbox
                 WHERE state = 'pending' AND quarantined_at IS NOT NULL
                 ORDER BY quarantined_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(rows
            .into_iter()
            .map(|row| OutboxKey {
                workspace_id: row.get(0),
                namespace_id: row.get(1),
                event_id: row.get::<_, Uuid>(2).to_string(),
            })
            .collect())
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        let count: i64 = self
            .client
            .query_one(
                "SELECT COUNT(*) FROM apex_event_outbox
                 WHERE state = 'pending' AND quarantined_at IS NOT NULL",
                &[],
            )
            .map_err(|_| GatewayError::internal())?
            .get(0);
        count.try_into().map_err(|_| GatewayError::internal())
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut workspaces = Vec::with_capacity(keys.len());
        let mut namespaces = Vec::with_capacity(keys.len());
        let mut event_ids = Vec::with_capacity(keys.len());
        for key in keys {
            workspaces.push(key.workspace_id.clone());
            namespaces.push(key.namespace_id.clone());
            event_ids.push(Uuid::from_str(&key.event_id).map_err(|_| GatewayError::internal())?);
        }
        self.client
            .execute(
                "UPDATE apex_event_outbox
                 SET quarantined_at = NULL, quarantine_reason = NULL,
                     attempts = 0, next_attempt_at = now()
                 WHERE state = 'pending' AND quarantined_at IS NOT NULL
                   AND (workspace_id, namespace_id, event_id) IN
                       (SELECT * FROM unnest($1::text[], $2::text[], $3::uuid[]))",
                &[&workspaces, &namespaces, &event_ids],
            )
            .map_err(|_| GatewayError::internal())?;
        Ok(())
    }

    /// Age, in milliseconds, of the oldest non-quarantined pending row.
    /// `created_at` is set once at INSERT (see `deploy/postgres/outbox.sql`)
    /// and never updated by `reschedule`/`pending_batch`'s claim, so this is
    /// the original enqueue time, not the most recent retry attempt --
    /// exactly the "how long has this actually been stuck" signal Phase 0.6
    /// item 6 needs. `min(created_at)` over zero matching rows returns SQL
    /// NULL, which `Option<f64>` decodes as `None` -- no separate empty-outbox
    /// branch needed.
    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        let age_millis: Option<f64> = self
            .client
            .query_one(
                "SELECT EXTRACT(EPOCH FROM (now() - min(created_at))) * 1000.0
                 FROM apex_event_outbox
                 WHERE state = 'pending' AND quarantined_at IS NULL",
                &[],
            )
            .map_err(|_| GatewayError::internal())?
            .get(0);
        Ok(age_millis.map(|value| value.max(0.0) as u64))
    }
}
