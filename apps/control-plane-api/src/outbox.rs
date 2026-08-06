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
