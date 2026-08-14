//! Shares one non-Postgres outbox handle between admission and the
//! dedicated fanout worker (Phase 0.6).
//!
//! Postgres gives each actor its own connection and relies on row locking
//! (`SELECT ... FOR UPDATE SKIP LOCKED`, see `outbox/postgres_replay.rs`'s
//! `pending_batch`) for concurrency safety across independent connections.
//! `FileOutbox` and `InMemoryOutbox` are single-writer, in-process lab/
//! embedded backends: `FileOutbox` holds an OS-level exclusive lock on its
//! journal for the life of the process, and both backends cache
//! pending/complete state in an in-process `HashMap` rather than
//! re-deriving it from shared storage on every call. Two independently
//! opened instances against the same file would therefore not merely
//! contend -- they would each hold a stale view of the other's writes.
//!
//! `SharedOutbox` is the fix for that class of backend: one real
//! `EventOutbox` instance behind an `Arc<Mutex<_>>`, cloned into both the
//! admission path's `OutboxedPublisher` and the fanout worker's. They
//! serialize on this mutex instead of diverging in memory. This is an
//! accepted lab-profile trade-off, not the scale target -- the scale target
//! is Postgres, where admission and the worker hold genuinely independent
//! connections instead.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{GatewayError, IngestRequest};

#[derive(Clone)]
pub struct SharedOutbox(Arc<Mutex<Box<dyn EventOutbox>>>);

impl SharedOutbox {
    pub fn new(inner: Box<dyn EventOutbox>) -> Self {
        Self(Arc::new(Mutex::new(inner)))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Box<dyn EventOutbox>>, GatewayError> {
        self.0.lock().map_err(|_| GatewayError::internal())
    }
}

impl EventOutbox for SharedOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        self.lock()?.enqueue(event)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        self.lock()?.mark_complete(key)
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        self.lock()?.mark_complete_many(keys)
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        self.lock()?.pending_batch(limit)
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        self.lock()?.pending_count()
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        self.lock()?.recent_completed_batch(since_millis, limit)
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        self.lock()?.pending_reconciliation_batch(limit)
    }

    fn reschedule(&mut self, keys: &[OutboxKey], after: Duration) -> Result<(), GatewayError> {
        self.lock()?.reschedule(keys, after)
    }

    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError> {
        self.lock()?.quarantine(keys, reason)
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        self.lock()?.quarantined_batch(limit)
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        self.lock()?.quarantined_count()
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        self.lock()?.requeue_quarantined(keys)
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        self.lock()?.maintain(now_millis, retention_millis)
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.lock()
            .map(|mut guard| guard.pending())
            .unwrap_or_default()
    }

    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        self.lock()?.oldest_pending_millis()
    }
}
