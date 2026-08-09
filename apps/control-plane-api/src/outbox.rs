//! Durable command outbox. Reuses `apex_event_ingest`'s `EventOutbox`
//! implementations (`InMemoryOutbox`, `FileOutbox`, and -- with the
//! `postgres` feature -- `PostgresOutbox`) instead of forking a second
//! durability story.
//!
//! Acceptance is intentionally decoupled from fanout (ADR-0006 requirement:
//! reachable even when JetStream/ClickHouse are degraded). `submit_command`
//! only enqueues the row; it never calls a publisher. A command is durable
//! -- and this call returns success -- the moment the outbox commits it,
//! whether or not the primary data path is currently reachable. Fanout is
//! [`crate::replay::spawn_fanout_worker`]'s job, running asynchronously and
//! retrying until it succeeds.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use apex_event_ingest::{EnqueueResult, EventOutbox, GatewayError, GatewayErrorCode, IngestRequest};

use crate::errors::CommandError;

pub struct ControlOutboxBackend {
    inner: BackendInner,
}

enum BackendInner {
    Single(Mutex<Box<dyn EventOutbox + Send>>),
    Pool {
        connections: Vec<Mutex<Box<dyn EventOutbox + Send>>>,
        next: AtomicUsize,
    },
}

impl ControlOutboxBackend {
    pub fn new(outbox: Box<dyn EventOutbox + Send>) -> Self {
        Self {
            inner: BackendInner::Single(Mutex::new(outbox)),
        }
    }

    /// Creates a bounded pool of independent durable backends. The gateway
    /// uses this for Postgres so submissions, replay, reconciliation, and
    /// maintenance do not queue behind one synchronous client connection.
    pub fn new_pool(outboxes: Vec<Box<dyn EventOutbox + Send>>) -> Result<Self, CommandError> {
        if outboxes.is_empty() {
            return Err(CommandError::internal());
        }
        Ok(Self {
            inner: BackendInner::Pool {
                connections: outboxes.into_iter().map(Mutex::new).collect(),
                next: AtomicUsize::new(0),
            },
        })
    }

    pub(crate) fn with_lock<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn EventOutbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        match &self.inner {
            BackendInner::Single(inner) => {
                let mut guard = inner.lock().map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
            BackendInner::Pool { connections, next } => {
                let index = next.fetch_add(1, Ordering::Relaxed) % connections.len();
                let mut guard = connections[index]
                    .lock()
                    .map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
        }
    }

    /// [`Self::with_lock`] for callers already inside an async task.
    ///
    /// Every `EventOutbox` implementation here is synchronous, and
    /// `PostgresOutbox` is synchronous the hard way: the `postgres` crate
    /// drives an internal tokio runtime and `block_on`s it on *every* query,
    /// which **panics** with "Cannot start a runtime from within a runtime"
    /// when called on a tokio worker thread. So an async caller cannot simply
    /// call `with_lock` -- the accept path
    /// ([`crate::service`]) already avoids this by going through
    /// `spawn_blocking`, and this is the equivalent primitive for callers
    /// that hold state across the call and cannot move it to another thread
    /// (the fanout worker holds the publisher guard).
    ///
    /// `block_in_place` is what licenses the nested `block_on`: it converts
    /// this worker thread into a blocking one and lets the runtime migrate
    /// other tasks off it. It is multi-thread-only and panics on a
    /// current-thread runtime, hence the flavor check -- outside a
    /// multi-thread runtime there is no worker thread to protect and the call
    /// is made directly, which is also what keeps the paused-clock tests in
    /// [`crate::replay`] deterministic.
    pub(crate) fn with_lock_from_async<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn EventOutbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(|| self.with_lock(f))
            }
            _ => self.with_lock(f),
        }
    }

    pub fn maintain(
        &self,
        now_millis: u64,
        retention_millis: u64,
    ) -> Result<(), CommandError> {
        self.with_lock(|outbox| outbox.maintain(now_millis, retention_millis))??;
        Ok(())
    }

    pub fn pending_batch(&self, limit: usize) -> Result<Vec<IngestRequest>, CommandError> {
        Ok(self.with_lock(|outbox| outbox.pending_batch(limit))??)
    }

    pub fn recent_completed_batch(
        &self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, CommandError> {
        Ok(self.with_lock(|outbox| outbox.recent_completed_batch(since_millis, limit))??)
    }

    pub fn pending_reconciliation_batch(
        &self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, CommandError> {
        Ok(self.with_lock(|outbox| outbox.pending_reconciliation_batch(limit))??)
    }

    pub(crate) fn reschedule(
        &self,
        keys: &[apex_event_ingest::OutboxKey],
        after: Duration,
    ) -> Result<(), CommandError> {
        self.with_lock_from_async(|outbox| outbox.reschedule(keys, after))??;
        Ok(())
    }

    pub(crate) fn quarantine(
        &self,
        keys: &[apex_event_ingest::OutboxKey],
        reason: &'static str,
    ) -> Result<(), CommandError> {
        self.with_lock_from_async(|outbox| outbox.quarantine(keys, reason))??;
        Ok(())
    }

    pub fn quarantined_batch(
        &self,
        limit: usize,
    ) -> Result<Vec<apex_event_ingest::OutboxKey>, CommandError> {
        Ok(self.with_lock(|outbox| outbox.quarantined_batch(limit))??)
    }

    pub fn quarantined_count(&self) -> Result<u64, CommandError> {
        Ok(self.with_lock(|outbox| outbox.quarantined_count())??)
    }

    pub fn requeue_quarantined(
        &self,
        keys: &[apex_event_ingest::OutboxKey],
    ) -> Result<(), CommandError> {
        self.with_lock(|outbox| outbox.requeue_quarantined(keys))??;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitOutcome {
    /// True when this `command_id` was already durably accepted before this
    /// call (same fields). The command is still recorded exactly once.
    pub duplicate: bool,
    /// True once fanout to the primary trace has completed. False means the
    /// command is durably accepted but delivery is still pending -- not
    /// lost, not retried destructively, just not yet visible downstream.
    pub delivered: bool,
}

/// Durably enqueues a validated command. Never blocks on, or fails because
/// of, downstream fanout availability.
pub fn submit_command(
    backend: &ControlOutboxBackend,
    request: &IngestRequest,
) -> Result<SubmitOutcome, CommandError> {
    let result = backend.with_lock(|outbox| outbox.enqueue(request))??;
    Ok(match result {
        EnqueueResult::Enqueued => SubmitOutcome {
            duplicate: false,
            delivered: false,
        },
        EnqueueResult::AlreadyPending => SubmitOutcome {
            duplicate: true,
            delivered: false,
        },
        EnqueueResult::AlreadyComplete => SubmitOutcome {
            duplicate: true,
            delivered: true,
        },
    })
}

impl From<apex_event_ingest::GatewayError> for CommandError {
    fn from(error: apex_event_ingest::GatewayError) -> Self {
        CommandError::from_gateway_error(&error)
    }
}

/// Rebuilds a synchronous Postgres client after a transport-level failure.
///
/// `postgres::Client` is intentionally kept behind the gateway's bounded
/// backend pool, but a client whose TCP connection dies is not self-healing.
/// Retrying only internal/storage errors is safe here: enqueue and settlement
/// are idempotent, while a claim may be delivered again under the existing
/// at-least-once contract.
#[cfg(feature = "postgres")]
pub struct RecoveringPostgresOutbox {
    connection_string: String,
    capacity: usize,
    inner: apex_event_ingest::PostgresOutbox,
}

#[cfg(feature = "postgres")]
impl RecoveringPostgresOutbox {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, GatewayError> {
        let inner = apex_event_ingest::PostgresOutbox::connect(connection_string, capacity)?;
        Ok(Self {
            connection_string: connection_string.to_owned(),
            capacity,
            inner,
        })
    }

    fn with_retry<T>(
        &mut self,
        mut operation: impl FnMut(&mut apex_event_ingest::PostgresOutbox) -> Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        match operation(&mut self.inner) {
            Ok(value) => Ok(value),
            Err(error) if error.code == GatewayErrorCode::Internal => {
                let replacement = apex_event_ingest::PostgresOutbox::connect(
                    &self.connection_string,
                    self.capacity,
                )?;
                self.inner = replacement;
                operation(&mut self.inner)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(feature = "postgres")]
impl EventOutbox for RecoveringPostgresOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        self.with_retry(|inner| inner.enqueue(event))
    }

    fn mark_complete(&mut self, key: &apex_event_ingest::OutboxKey) -> Result<(), GatewayError> {
        self.with_retry(|inner| inner.mark_complete(key))
    }

    fn mark_complete_many(
        &mut self,
        keys: &[apex_event_ingest::OutboxKey],
    ) -> Result<(), GatewayError> {
        self.with_retry(|inner| inner.mark_complete_many(keys))
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        self.with_retry(|inner| inner.pending_batch(limit))
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        self.with_retry(|inner| inner.recent_completed_batch(since_millis, limit))
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        self.with_retry(|inner| inner.pending_reconciliation_batch(limit))
    }

    fn reschedule(
        &mut self,
        keys: &[apex_event_ingest::OutboxKey],
        after: Duration,
    ) -> Result<(), GatewayError> {
        self.with_retry(|inner| inner.reschedule(keys, after))
    }

    fn quarantine(
        &mut self,
        keys: &[apex_event_ingest::OutboxKey],
        reason: &'static str,
    ) -> Result<(), GatewayError> {
        self.with_retry(|inner| inner.quarantine(keys, reason))
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        self.with_retry(|inner| inner.maintain(now_millis, retention_millis))
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.with_retry(|inner| Ok(inner.pending_batch(10_000).unwrap_or_default()))
            .unwrap_or_default()
    }
}
