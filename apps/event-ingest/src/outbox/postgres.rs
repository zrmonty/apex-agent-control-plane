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

/// Outcome of comparing a cheap row-count estimate against the capacity
/// ceiling: trust it outright in either direction, or fall back to an exact
/// count when it is too close to the ceiling to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CapacityDecision {
    Allow,
    Deny,
    ExactRecheck,
}

/// Decides admission from an approximate row count without ever letting the
/// estimate's error cross the ceiling undetected.
///
/// `margin` must bound how far `estimate` can realistically diverge from the
/// true count, in either direction (see `capacity_margin`). Given that bound,
/// the three-way split is sound: if `estimate + margin < capacity`, the true
/// count is at most `estimate + margin`, which is still under capacity, so
/// admitting is safe even in the worst case. Symmetrically, if
/// `estimate - margin >= capacity`, the true count is at least
/// `estimate - margin`, which already reached capacity, so denying is safe.
/// Only the band in between -- where the estimate's own error could place the
/// true count on either side of the ceiling -- needs the exact recheck.
pub(super) fn capacity_decision(estimate: i64, capacity: usize, margin: usize) -> CapacityDecision {
    let estimate = u64::try_from(estimate).unwrap_or(0);
    let capacity = capacity as u64;
    let margin = margin as u64;
    if estimate.saturating_add(margin) < capacity {
        CapacityDecision::Allow
    } else if estimate.saturating_sub(margin) >= capacity {
        CapacityDecision::Deny
    } else {
        CapacityDecision::ExactRecheck
    }
}

/// Safety margin an `n_live_tup` estimate must clear before it is trusted
/// outright.
///
/// `n_live_tup` (`pg_stat_user_tables`) is Postgres's incrementally
/// maintained live-tuple counter: every insert/delete adjusts it and the
/// cumulative stats system flushes the change to shared memory in well under
/// a second, regardless of table size. That is a fundamentally different
/// staleness story from `pg_class.reltuples`, which only moves on `ANALYZE`
/// or autovacuum and can sit at zero on a freshly created table indefinitely.
/// A 5% margin, floored at 64 rows, comfortably covers that sub-second flush
/// lag plus a burst of concurrent admissions landing inside it. It only
/// matters near the ceiling (see `capacity_decision`): a backlog far from
/// capacity can absorb far more estimate error than this without ever
/// mis-admitting or mis-denying.
pub(super) fn capacity_margin(capacity: usize) -> usize {
    (capacity / 20).max(64).min(capacity.max(1))
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
        // The capacity check used to be an unconditional `SELECT COUNT(*)` on
        // every enqueue: a full sequential scan that gets slower as the
        // backlog it exists to bound grows -- a compounding failure under
        // load. `n_live_tup` is Postgres's own incrementally maintained
        // live-row estimate (see `capacity_margin`): reading it is an O(1)
        // shared-memory lookup, not a table scan, and unlike a dedicated
        // counter row it is written by Postgres's existing stats machinery
        // outside this transaction, so concurrent admissions never contend
        // with each other over a shared row (that would only trade one
        // bottleneck for a worse one). The estimate is trusted outright
        // everywhere except a margin-wide band around the ceiling, where an
        // exact recount -- the old query, now rare -- settles it. See
        // `capacity_decision`.
        let estimate: i64 = tx
            .query_opt(
                "SELECT n_live_tup FROM pg_stat_user_tables
                 WHERE relid = 'apex_event_outbox'::regclass",
                &[],
            )
            .map_err(|_| GatewayError::internal())?
            .map(|row| row.get(0))
            .unwrap_or(0);
        match capacity_decision(estimate, self.capacity, capacity_margin(self.capacity)) {
            CapacityDecision::Allow => {}
            CapacityDecision::Deny => {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
            }
            CapacityDecision::ExactRecheck => {
                let total: i64 = tx
                    .query_one("SELECT COUNT(*) FROM apex_event_outbox", &[])
                    .map_err(|_| GatewayError::internal())?
                    .get(0);
                if total as usize >= self.capacity {
                    return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
                }
            }
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

    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        PostgresReplayOps::oldest_pending_millis(self)
    }
}

/// `capacity_decision` / `capacity_margin` are pure functions with no
/// database dependency, so their correctness is covered here rather than in
/// `postgres_tests.rs` (which needs `APEX_POSTGRES_URL`).
#[cfg(test)]
mod capacity_estimate_tests {
    use super::{CapacityDecision, capacity_decision, capacity_margin};

    #[test]
    fn allows_when_estimate_plus_margin_is_below_capacity() {
        assert_eq!(
            capacity_decision(100, 1_000, 50),
            CapacityDecision::Allow
        );
        // Exactly at the boundary (estimate + margin == capacity) must NOT
        // allow: the true count could equal capacity in the worst case.
        assert_eq!(
            capacity_decision(950, 1_000, 50),
            CapacityDecision::ExactRecheck
        );
    }

    #[test]
    fn denies_when_estimate_minus_margin_reaches_capacity() {
        assert_eq!(capacity_decision(1_060, 1_000, 50), CapacityDecision::Deny);
        // Exactly at the boundary (estimate - margin == capacity) must deny:
        // the true count is guaranteed to be at least capacity.
        assert_eq!(capacity_decision(1_050, 1_000, 50), CapacityDecision::Deny);
    }

    #[test]
    fn rechecks_exactly_in_the_ambiguous_band() {
        // capacity=1000, margin=50: band is [951, 1049] inclusive-ish where
        // neither Allow's nor Deny's soundness bound is met.
        for estimate in [951, 975, 1_000, 1_025, 1_049] {
            assert_eq!(
                capacity_decision(estimate, 1_000, 50),
                CapacityDecision::ExactRecheck,
                "estimate={estimate} should require an exact recheck"
            );
        }
    }

    #[test]
    fn negative_estimate_is_clamped_to_zero_not_denied() {
        // Postgres stats can transiently report values this code should
        // treat as "no information", never as a signal to deny outright.
        assert_eq!(capacity_decision(-5, 1_000, 50), CapacityDecision::Allow);
    }

    #[test]
    fn zero_capacity_never_panics_and_denies() {
        // connect() already rejects capacity == 0, but the decision function
        // itself must still be total (no panics) for any input.
        assert_eq!(capacity_decision(0, 0, capacity_margin(0)), CapacityDecision::Deny);
        assert_eq!(capacity_decision(5, 0, capacity_margin(0)), CapacityDecision::Deny);
    }

    #[test]
    fn margin_is_a_five_percent_floor_of_64_capped_at_capacity() {
        assert_eq!(capacity_margin(1_000_000), 50_000);
        assert_eq!(capacity_margin(100), 64); // 5% of 100 is 5, floored to 64
        assert_eq!(capacity_margin(64), 64); // 5% of 64 is 3, floored to 64, capped at 64
        assert_eq!(capacity_margin(1), 1); // floor of 64 capped down to capacity itself
        assert_eq!(capacity_margin(4_096), 204); // 5% of 4096 = 204 (integer division)
    }

    #[test]
    fn margin_never_exceeds_capacity() {
        for capacity in [0usize, 1, 2, 63, 64, 65, 1_000, 999_999, 1_000_000] {
            assert!(
                capacity_margin(capacity) <= capacity.max(1),
                "margin for capacity={capacity} must never exceed the capacity itself"
            );
        }
    }

    #[test]
    fn large_capacity_near_the_documented_maximum_does_not_overflow() {
        // connect() enforces capacity <= 1_000_000, but the decision function
        // itself must stay correct well beyond that for any i64 estimate.
        let capacity = 1_000_000usize;
        let margin = capacity_margin(capacity);
        assert_eq!(
            capacity_decision(i64::MAX, capacity, margin),
            CapacityDecision::Deny
        );
    }
}
