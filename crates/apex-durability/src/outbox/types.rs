use std::time::Duration;

use crate::{GatewayError, IngestRequest};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboxKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    Enqueued,
    AlreadyPending,
    AlreadyComplete,
}

/// Durable outbox contract. `enqueue` must commit the canonical event before
/// the downstream fanout begins; `mark_complete` is only called after every
/// projection acknowledges the event. Pending rows are replay work.
pub trait EventOutbox: Send {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError>;
    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError>;

    /// Settles a group of successfully published events. Implementations may
    /// use one durable write/transaction; the default preserves the original
    /// per-key behavior for small or embedded backends.
    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        for key in keys {
            self.mark_complete(key)?;
        }
        Ok(())
    }

    /// Returns at most `limit` pending events. The default preserves the
    /// original backend contract; durable backends should override it so a
    /// large backlog is bounded before it reaches the replay worker.
    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        let mut events = self.pending();
        events.truncate(limit);
        Ok(events)
    }

    /// Returns the number of non-quarantined rows awaiting fanout. Durable
    /// backends override this with a count query; the default is for small
    /// embedded stores.
    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        Ok(self.pending().len() as u64)
    }

    /// Returns recently completed events so a gateway can repair a delivery
    /// record that was lost after fanout completed. Backends that cannot
    /// reconstruct completed payloads may return an empty batch.
    fn recent_completed_batch(
        &mut self,
        _since_millis: u64,
        _limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(Vec::new())
    }

    /// Returns pending events without claiming them or changing retry state.
    /// Reconciliation uses this read-only view so it cannot steal a replay
    /// lease or inflate delivery attempts while repairing the inbox.
    fn pending_reconciliation_batch(
        &mut self,
        _limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(Vec::new())
    }

    /// Releases failed claims for a bounded retry. Backends without leases
    /// can keep their existing next-cycle behaviour.
    fn reschedule(&mut self, _keys: &[OutboxKey], _after: Duration) -> Result<(), GatewayError> {
        Ok(())
    }

    /// Removes a poison row from the replay work set while retaining its
    /// durable idempotency identity for operator remediation.
    fn quarantine(
        &mut self,
        _keys: &[OutboxKey],
        _reason: &'static str,
    ) -> Result<(), GatewayError> {
        Ok(())
    }

    /// Lists quarantined identities for operator tooling. Payloads are not
    /// returned by this inventory method.
    fn quarantined_batch(&mut self, _limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        Ok(Vec::new())
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        Ok(0)
    }

    /// Age, in milliseconds, of the oldest non-quarantined pending row --
    /// `None` when the outbox currently holds no pending work. This is the
    /// second half of Phase 0.6 item 6's early-warning signal alongside
    /// `pending_count`: a shallow-but-stuck backlog (a handful of rows that
    /// never drain) looks fine on depth alone but is exactly what this
    /// answers. The default returns `Ok(None)` unconditionally -- "age not
    /// tracked" -- so a hypothetical future backend that does not implement
    /// this still compiles; every backend actually wired into the gateway
    /// (`InMemoryOutbox`, `FileOutbox`, `PostgresOutbox`) overrides it.
    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        Ok(None)
    }

    /// Requeues selected quarantined rows for another bounded replay attempt.
    /// This is intentionally a separate operation from normal submission so
    /// remediation is explicit and can be audited by the caller.
    fn requeue_quarantined(&mut self, _keys: &[OutboxKey]) -> Result<(), GatewayError> {
        Ok(())
    }

    /// Removes completed idempotency state outside the configured retention
    /// window and compacts file journals where applicable.
    fn maintain(&mut self, _now_millis: u64, _retention_millis: u64) -> Result<(), GatewayError> {
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest>;
}

impl<T: EventOutbox + ?Sized> EventOutbox for Box<T> {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        (**self).enqueue(event)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        (**self).mark_complete(key)
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        (**self).mark_complete_many(keys)
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        (**self).pending_batch(limit)
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        (**self).pending_count()
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        (**self).recent_completed_batch(since_millis, limit)
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        (**self).pending_reconciliation_batch(limit)
    }

    fn reschedule(&mut self, keys: &[OutboxKey], after: Duration) -> Result<(), GatewayError> {
        (**self).reschedule(keys, after)
    }

    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError> {
        (**self).quarantine(keys, reason)
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        (**self).quarantined_batch(limit)
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        (**self).quarantined_count()
    }

    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        (**self).oldest_pending_millis()
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        (**self).requeue_quarantined(keys)
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        (**self).maintain(now_millis, retention_millis)
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        (**self).pending()
    }
}
