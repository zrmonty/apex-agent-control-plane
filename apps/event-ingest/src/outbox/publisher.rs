use std::collections::HashMap;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{EventPublisher, GatewayError, IngestRequest, PublishOutcome};

/// Mirrors the durable retry ceiling both `FileOutbox` (`MAX_PERSISTED_ATTEMPTS`
/// in `outbox/file.rs`) and `PostgresOutbox` (the `attempts >= 8` predicate in
/// `outbox/postgres_replay.rs`) already enforce inside their own `reschedule`.
/// This copy is not the authority on when a row actually gets quarantined --
/// each backend's own durable attempt count is -- it only bounds how long
/// `OutboxedPublisher::retry_attempts` holds an entry, so a key long since
/// quarantined by the backend cannot accumulate here for the life of the
/// process.
const MAX_REPLAY_ATTEMPTS: u32 = 8;
const MIN_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Deterministic per-key jitter keeps replicas that fail on the same key from
/// retrying it in lockstep, without pulling in an RNG for a synchronous retry
/// path or making tests nondeterministic.
fn retry_delay(key: &OutboxKey, attempts: u32) -> Duration {
    let multiplier = 1_u64 << attempts.min(4);
    let base = MIN_RETRY_DELAY
        .saturating_mul(multiplier as u32)
        .min(MAX_RETRY_DELAY);
    let mut input = Vec::new();
    input.extend_from_slice(key.workspace_id.as_bytes());
    input.push(0);
    input.extend_from_slice(key.namespace_id.as_bytes());
    input.push(0);
    input.extend_from_slice(key.event_id.as_bytes());
    let digest = Sha256::digest(input);
    let jitter_millis = u16::from_be_bytes([digest[0], digest[1]]) as u64 % 1_000;
    base + Duration::from_millis(jitter_millis)
}

pub struct OutboxedPublisher<P, O> {
    pub(crate) publisher: P,
    pub(crate) outbox: O,
    /// In-process failure counter used only to pick this worker's next
    /// backoff for a still-failing key; it is advisory, not authoritative.
    /// The durable ceiling that actually decides quarantine lives in each
    /// `EventOutbox::reschedule` implementation, keyed off its own durable
    /// attempt count, so a freshly started process (no local history) still
    /// converges on the same outcome as a long-running one.
    retry_attempts: HashMap<OutboxKey, u32>,
}

pub trait PendingEventReplayer {
    fn replay_pending(&mut self) -> Result<(), GatewayError>;
}

/// Lets a generic `IngestGateway<P>` conditionally expose the durable
/// outbox's retention sweep only when its concrete publisher actually wraps
/// one, mirroring how `PendingEventReplayer` conditionally exposes replay.
pub trait OutboxMaintainer {
    fn maintain_outbox(&mut self, now_millis: u64, retention_millis: u64)
    -> Result<(), GatewayError>;
}

impl<P, O> OutboxedPublisher<P, O> {
    pub fn new(publisher: P, outbox: O) -> Self {
        Self {
            publisher,
            outbox,
            retry_attempts: HashMap::new(),
        }
    }

    pub fn publisher(&self) -> &P {
        &self.publisher
    }

    pub fn outbox(&self) -> &O {
        &self.outbox
    }

    pub fn outbox_mut(&mut self) -> &mut O {
        &mut self.outbox
    }
}

impl<P, O> OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    /// Replays rows that were durably enqueued before a previous process
    /// stopped. This must run before the live server accepts traffic so a
    /// pending row cannot be mistaken for a successful duplicate.
    ///
    /// A single event's publish failure -- a sink that 4xx/5xx's forever, not
    /// a malformed row, which `pending`/`pending_batch` quarantine separately
    /// -- must never abort replay for every other event sharing this outbox.
    /// `pending()` on the durable backends claims rows oldest-first, so
    /// without per-event isolation here the oldest permanently-failing row
    /// starves every other tenant's replay on every single cycle. Each
    /// event's outcome is therefore isolated instead of `?`-propagated out of
    /// the loop, mirroring `control-plane-api/src/replay.rs`'s fanout worker.
    fn replay_pending_inner(&mut self) -> Result<(), GatewayError> {
        let pending = self.outbox.pending();
        let mut completed = Vec::with_capacity(pending.len());
        let mut failed = Vec::new();
        for event in pending {
            let key = OutboxKey {
                workspace_id: event.workspace_id.clone(),
                namespace_id: event.namespace_id.clone(),
                event_id: event.event_id.clone(),
            };
            // The outcome is not meaningful here: `self.publisher` is the
            // fanout, not another outbox, so it always reports Published.
            match self.publisher.publish(&event) {
                Ok(_outcome) => completed.push(key),
                Err(error) => {
                    eprintln!(
                        "event-ingest outbox replay deferred: {}: {}",
                        error.code.public_code(),
                        error.summary
                    );
                    failed.push(key);
                }
            }
        }

        let mut first_durable_error = None;
        if !completed.is_empty() {
            match self.outbox.mark_complete_many(&completed) {
                Ok(()) => {
                    for key in &completed {
                        self.retry_attempts.remove(key);
                    }
                }
                Err(error) => {
                    eprintln!(
                        "event-ingest outbox replay: failed to settle {} completed row(s): {}: {}",
                        completed.len(),
                        error.code.public_code(),
                        error.summary
                    );
                    // Published but not durably settled: keep it a replay
                    // candidate rather than forgetting it. Fanout is
                    // idempotent on event_id, so the next cycle republishing
                    // it is safe.
                    failed.extend(completed);
                    first_durable_error = Some(error);
                }
            }
        }

        if !failed.is_empty() {
            let mut retry_groups: HashMap<Duration, Vec<OutboxKey>> = HashMap::new();
            for key in failed {
                let attempts = {
                    let counter = self.retry_attempts.entry(key.clone()).or_insert(0);
                    *counter = counter.saturating_add(1);
                    *counter
                };
                if attempts >= MAX_REPLAY_ATTEMPTS {
                    self.retry_attempts.remove(&key);
                }
                let delay = retry_delay(&key, attempts);
                retry_groups.entry(delay).or_default().push(key);
            }
            // Each backend's `reschedule` owns the actual attempts-vs-ceiling
            // decision (durably tracked, not the local counter above): below
            // the ceiling it pushes `next_attempt_at` out by `delay`; at or
            // past it, it quarantines the row instead. That is what makes the
            // ladder in the finding -- "reschedule has zero production call
            // sites, so nothing is ever quarantined" -- actually fire.
            for (delay, keys) in retry_groups {
                if let Err(error) = self.outbox.reschedule(&keys, delay) {
                    eprintln!(
                        "event-ingest outbox replay: failed to reschedule {} row(s): {}: {}",
                        keys.len(),
                        error.code.public_code(),
                        error.summary
                    );
                    if first_durable_error.is_none() {
                        first_durable_error = Some(error);
                    }
                }
            }
        }

        match first_durable_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<P, O> PendingEventReplayer for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn replay_pending(&mut self) -> Result<(), GatewayError> {
        self.replay_pending_inner()
    }
}

impl<P, O> OutboxMaintainer for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn maintain_outbox(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
    ) -> Result<(), GatewayError> {
        self.outbox.maintain(now_millis, retention_millis)
    }
}

impl<P, O> EventPublisher for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn can_reconcile_commit_failure(&self) -> bool {
        true
    }

    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        match self.outbox.enqueue(event)? {
            // The outbox already holds a completed row for this exact payload
            // (post-9734d9a `AlreadyComplete` is fingerprint-matched, so this
            // really is the same event, not merely the same id). Say so
            // instead of returning a bare Ok that the caller cannot tell apart
            // from a fresh publish.
            EnqueueResult::AlreadyComplete => return Ok(PublishOutcome::AlreadyComplete),
            EnqueueResult::AlreadyPending => {
                // A live request must never race a replay worker or another
                // request into a second fanout. Workers need a separate claim
                // API that atomically transfers ownership before publishing.
                return Err(GatewayError::new(
                    crate::GatewayErrorCode::IdempotencyInProgress,
                ));
            }
            EnqueueResult::Enqueued => {}
        }
        self.publisher.publish(event)?;
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        self.outbox.mark_complete(&key)?;
        Ok(PublishOutcome::Published)
    }
}
