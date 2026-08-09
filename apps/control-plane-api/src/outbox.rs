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
use std::time::Duration;

use apex_event_ingest::{EnqueueResult, EventOutbox, IngestRequest};

use crate::errors::CommandError;

pub struct ControlOutboxBackend {
    inner: Mutex<Box<dyn EventOutbox + Send>>,
}

impl ControlOutboxBackend {
    pub fn new(outbox: Box<dyn EventOutbox + Send>) -> Self {
        Self {
            inner: Mutex::new(outbox),
        }
    }

    pub(crate) fn with_lock<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn EventOutbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        let mut guard = self.inner.lock().map_err(|_| CommandError::internal())?;
        Ok(f(&mut guard))
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
        self.with_lock(|outbox| outbox.pending_batch(limit))
    }

    pub(crate) fn reschedule(
        &self,
        keys: &[apex_event_ingest::OutboxKey],
        after: Duration,
    ) -> Result<(), CommandError> {
        self.with_lock_from_async(|outbox| outbox.reschedule(keys, after))??;
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
