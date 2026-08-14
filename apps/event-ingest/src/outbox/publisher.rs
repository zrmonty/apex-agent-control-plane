use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
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
    /// Runs one replay cycle. Returns `Ok(true)` when the cycle durably
    /// settled (`mark_complete_many`) at least one previously pending event,
    /// `Ok(false)` when there was nothing pending or nothing this cycle
    /// actually settled (every claimed row failed to publish or failed to
    /// settle). `spawn_fanout_worker` uses this signal to decide whether to
    /// loop again immediately -- there may be more real backlog waiting right
    /// now -- or fall back to its polling interval, which is also this
    /// worker's only throttle against spinning on a stuck sink or a stuck
    /// outbox. See `replay_pending_inner` for why "settled" (not merely
    /// "claimed") is the right signal.
    fn replay_pending(&mut self) -> Result<bool, GatewayError>;
}

/// Lets a generic `IngestGateway<P>` conditionally expose the durable
/// outbox's retention sweep only when its concrete publisher actually wraps
/// one, mirroring how `PendingEventReplayer` conditionally exposes replay.
pub trait OutboxMaintainer {
    fn maintain_outbox(&mut self, now_millis: u64, retention_millis: u64)
    -> Result<(), GatewayError>;
}

/// Lets a generic `IngestGateway<P>` conditionally expose backlog depth/age
/// (Phase 0.6 item 6) only when its concrete publisher wraps a durable
/// outbox, mirroring `OutboxMaintainer` and `PendingEventReplayer` above.
/// Returns `(pending_count, oldest_pending_millis)` in one call so the
/// backlog monitor samples both signals from a single adapter lock instead
/// of two.
pub trait BacklogObserver {
    fn backlog_stats(&mut self) -> Result<(u64, Option<u64>), GatewayError>;
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
    ///
    /// Returns whether this cycle durably settled at least one event
    /// (`Ok(true)`), used by `spawn_fanout_worker` to decide whether to keep
    /// draining without sleeping. Deliberately keyed off *settlement*, not
    /// merely off `pending` being non-empty: a claimed batch where every row
    /// failed to publish (a sink outage) or failed to settle (the outbox
    /// itself misbehaving) means the very next cycle would almost certainly
    /// see the same rows again with no new information. Signalling "did
    /// work" for that case would spin this worker in a tight loop against a
    /// stuck sink -- burning CPU and, for the file/memory backends whose bare
    /// `pending()` does not gate on `next_attempt_at` (see
    /// `a_permanently_failing_event_is_quarantined_after_the_replay_ceiling_instead_of_retried_forever`
    /// in `outbox/tests_cases.rs`), racing an event through the entire
    /// `MAX_REPLAY_ATTEMPTS` ceiling in milliseconds and quarantining it for
    /// what may have been a sub-second blip. Gating on real settlement keeps
    /// this worker's only throttle (`interval`) intact for exactly the cases
    /// that need it, while still draining immediately whenever there is
    /// genuine forward progress to make.
    fn replay_pending_inner(&mut self) -> Result<bool, GatewayError> {
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
        let mut settled_any = false;
        if !completed.is_empty() {
            match self.outbox.mark_complete_many(&completed) {
                Ok(()) => {
                    settled_any = true;
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
            None => Ok(settled_any),
        }
    }
}

impl<P, O> PendingEventReplayer for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn replay_pending(&mut self) -> Result<bool, GatewayError> {
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

impl<P, O> BacklogObserver for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn backlog_stats(&mut self) -> Result<(u64, Option<u64>), GatewayError> {
        let depth = self.outbox.pending_count()?;
        let oldest_pending_millis = self.outbox.oldest_pending_millis()?;
        Ok((depth, oldest_pending_millis))
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

    /// Phase 0.6: admission is durable-enqueue-only. No downstream fanout
    /// happens on this call stack any more -- `self.publisher` (the actual
    /// JetStream/ClickHouse/archive fanout) is deliberately never called
    /// here. `Enqueued` maps to `Published`, which from this call forward
    /// means "durably committed to the outbox", not "delivered to every
    /// sink"; delivery is the dedicated fanout worker's job
    /// (`spawn_fanout_worker` below), running off a separate outbox handle
    /// so it never contends with admission's mutex. See
    /// `IngestGateway::ingest_inner` in `gateway/core.rs`, which maps this
    /// outcome to `IngestOutcome::Accepted` -- "durably enqueued", the same
    /// semantics change documented there.
    ///
    /// The `AlreadyPending`/`AlreadyComplete` handling is unchanged: a live
    /// request still never races a replay worker or another request into a
    /// second fanout, and a request for an already-completed event still
    /// never touches `self.publisher` either.
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        match self.outbox.enqueue(event)? {
            // The outbox already holds a completed row for this exact payload
            // (post-9734d9a `AlreadyComplete` is fingerprint-matched, so this
            // really is the same event, not merely the same id). Say so
            // instead of returning a bare Ok that the caller cannot tell apart
            // from a fresh publish.
            EnqueueResult::AlreadyComplete => Ok(PublishOutcome::AlreadyComplete),
            EnqueueResult::AlreadyPending => {
                // A live request must never race a replay worker or another
                // request into a second fanout. Workers need a separate claim
                // API that atomically transfers ownership before publishing.
                Err(GatewayError::new(
                    crate::GatewayErrorCode::IdempotencyInProgress,
                ))
            }
            EnqueueResult::Enqueued => Ok(PublishOutcome::Published),
        }
    }
}

/// Spawns the dedicated background fanout worker.
///
/// This is the PRIMARY fanout path as of Phase 0.6: `EventPublisher::publish`
/// above only durably enqueues, so nothing downstream of the outbox commit
/// runs on the admission call stack, and nothing downstream blocks on the
/// admission adapter's mutex (`AuthenticatedGrpcService`'s
/// `adapter: Arc<Mutex<...>>`) any more. This loop is what actually delivers
/// a durably-enqueued row to JetStream/ClickHouse/archive.
///
/// `worker` should own its OWN fanout publisher and its OWN outbox handle,
/// entirely separate from the admission path's -- a second `PostgresOutbox`
/// connection for the scale target, or a `SharedOutbox` handle shared with
/// admission for the file/memory lab backends (see
/// `startup::service::open_durability_stores`, the only production caller).
/// Either way, a slow archive PUT+verify in this loop never blocks a
/// concurrent `ingest` call.
///
/// Runs on a dedicated blocking OS thread (`spawn_blocking`), not a plain
/// `tokio::spawn` async task calling a sync method directly:
/// `PostgresOutbox` blocks its own internal runtime for every query (see
/// `control-plane-api/src/replay.rs`'s `with_lock_from_async` doc comment
/// for the exact hazard this avoids), which panics with "Cannot start a
/// runtime from within a runtime" if driven from a tokio worker thread.
/// `spawn_idempotency_reaper` in `startup/service.rs` uses the identical
/// pattern for the same reason.
///
/// Reuses `replay_pending`'s existing per-event isolation and bounded
/// backoff (`replay_pending_inner` above) unchanged: one permanently-failing
/// event is rescheduled and, past the backend's own durable attempt
/// ceiling, quarantined -- and never blocks any other row in the batch.
///
/// Phase 0.6 item 4 (continuous drain): a cycle that actually settled work
/// loops again immediately instead of waiting out `interval`, so a growing
/// backlog is drained at the outbox's/sinks' own speed rather than being
/// capped at one batch per `interval`. `interval` remains this worker's
/// sleep whenever a cycle found nothing pending, and -- just as importantly
/// -- whenever a cycle claimed rows but settled none of them (see
/// `replay_pending_inner`'s doc comment for why that case must not spin).
/// `startup::service::run` may spawn several of these concurrently, each
/// with its own `OutboxedPublisher` (own outbox handle, own fanout stack);
/// `pending_batch`'s `SELECT ... FOR UPDATE SKIP LOCKED` claim is what makes
/// that safe without any coordination between them.
pub fn spawn_fanout_worker<P, O>(
    mut worker: OutboxedPublisher<P, O>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
where
    P: EventPublisher + Send + 'static,
    O: EventOutbox + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        loop {
            let result = catch_unwind(AssertUnwindSafe(|| worker.replay_pending()))
                .unwrap_or_else(|_| Err(GatewayError::internal()));
            let did_settle_work = match result {
                Ok(did_settle_work) => did_settle_work,
                Err(error) => {
                    eprintln!(
                        "event-ingest fanout worker deferred: {}: {}",
                        error.code.public_code(),
                        error.summary
                    );
                    false
                }
            };
            if !did_settle_work {
                std::thread::sleep(interval);
            }
        }
    })
}
