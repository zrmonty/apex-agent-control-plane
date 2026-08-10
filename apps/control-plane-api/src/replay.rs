//! Best-effort, retrying fanout of durably accepted commands to the primary
//! trace (JetStream/ClickHouse, via an `apex_event_ingest::EventPublisher`).
//!
//! This worker is intentionally decoupled from the accept path
//! ([`crate::outbox::submit_command`]): a command is durable the moment the
//! outbox commits it, and this loop is what eventually delivers it once the
//! primary data path is reachable again. A stopped or degraded publisher
//! only delays `delivered = true`; it never loses or re-orders-into-loss a
//! command, and it never blocks a new `SubmitCommand` call.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use apex_event_ingest::{EventPublisher, OutboxKey};
use sha2::{Digest, Sha256};

use crate::outbox::ControlOutboxBackend;
use crate::status::{GatewayRuntimeMetrics, GatewayShutdown};

const FANOUT_BATCH_SIZE: usize = 256;
const MIN_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const MAX_REPLAY_ATTEMPTS: u32 = 8;

fn retry_delay(key: &OutboxKey, attempts: u32) -> Duration {
    let multiplier = 1_u64 << attempts.min(4);
    let base = MIN_RETRY_DELAY
        .saturating_mul(multiplier as u32)
        .min(MAX_RETRY_DELAY);
    // A deterministic per-key jitter keeps replicas from retrying a hot set
    // in lockstep without introducing a new RNG dependency or making tests
    // nondeterministic.
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

/// Spawns a loop that periodically drains pending outbox rows through
/// `publisher` and marks each complete on success. Failures are logged and
/// retried on the next interval; they never panic the worker or affect the
/// accept path.
pub fn spawn_fanout_worker<P>(
    backend: Arc<ControlOutboxBackend>,
    publisher: Arc<tokio::sync::Mutex<P>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
where
    P: EventPublisher + Send + 'static,
{
    spawn_fanout_worker_with_metrics_and_shutdown(backend, publisher, interval, None, None)
}

pub fn spawn_fanout_worker_with_metrics<P>(
    backend: Arc<ControlOutboxBackend>,
    publisher: Arc<tokio::sync::Mutex<P>>,
    interval: Duration,
    metrics: Option<Arc<GatewayRuntimeMetrics>>,
) -> tokio::task::JoinHandle<()>
where
    P: EventPublisher + Send + 'static,
{
    spawn_fanout_worker_with_metrics_and_shutdown(backend, publisher, interval, metrics, None)
}

pub fn spawn_fanout_worker_with_metrics_and_shutdown<P>(
    backend: Arc<ControlOutboxBackend>,
    publisher: Arc<tokio::sync::Mutex<P>>,
    interval: Duration,
    metrics: Option<Arc<GatewayRuntimeMetrics>>,
    shutdown: Option<GatewayShutdown>,
) -> tokio::task::JoinHandle<()>
where
    P: EventPublisher + Send + 'static,
{
    tokio::spawn(async move {
        let mut wait_for_tick = true;
        let mut failures: HashMap<OutboxKey, u32> = HashMap::new();
        let mut not_before: HashMap<OutboxKey, tokio::time::Instant> = HashMap::new();
        let mut draining = false;
        loop {
            if wait_for_tick {
                if let Some(shutdown) = &shutdown {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {}
                        _ = shutdown.wait() => { draining = true; }
                    }
                } else {
                    tokio::time::sleep(interval).await;
                }
            }
            let backend = backend.clone();
            // `with_lock_from_async`, not `with_lock`: `PostgresOutbox` runs
            // every query through the `postgres` crate's own internal runtime
            // and `block_on`, which panics on a tokio worker thread. See that
            // method's doc comment -- this exact call aborted the worker on
            // the first Postgres-backed container start.
            let pending: Vec<apex_event_ingest::IngestRequest> = match backend
                .with_lock_from_async(|outbox| outbox.pending_batch(FANOUT_BATCH_SIZE))
            {
                Ok(Ok(pending)) => {
                    if let Some(metrics) = &metrics {
                        metrics
                            .storage_healthy
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let now = tokio::time::Instant::now();
                    pending
                        .into_iter()
                        .filter(|event| {
                            let key = OutboxKey {
                                workspace_id: event.workspace_id().to_owned(),
                                namespace_id: event.namespace_id().to_owned(),
                                event_id: event.event_id().to_owned(),
                            };
                            not_before.get(&key).is_none_or(|deadline| *deadline <= now)
                        })
                        .collect()
                }
                Ok(Err(_)) | Err(_) => {
                    if let Some(metrics) = &metrics {
                        metrics
                            .storage_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .fanout_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Some(metrics) = &metrics {
                        metrics
                            .outbox_read_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if draining {
                        break;
                    }
                    wait_for_tick = true;
                    continue;
                }
            };
            if pending.is_empty() {
                if draining {
                    break;
                }
                wait_for_tick = true;
                continue;
            }
            if shutdown.as_ref().is_some_and(GatewayShutdown::is_requested) {
                draining = true;
            }
            let was_full_batch = pending.len() == FANOUT_BATCH_SIZE;
            let mut publisher_guard = publisher.lock().await;
            let mut completed = Vec::new();
            let mut failed = Vec::new();
            for event in pending {
                let key = OutboxKey {
                    workspace_id: event.workspace_id().to_owned(),
                    namespace_id: event.namespace_id().to_owned(),
                    event_id: event.event_id().to_owned(),
                };
                let publish_result = catch_unwind(AssertUnwindSafe(|| {
                    publisher_guard.publish(&event)
                }));
                match publish_result {
                    // Either outcome means the event is durable: Published
                    // because this call stored it, AlreadyComplete because a
                    // previous attempt did and the outbox proved it. Both must
                    // settle the row.
                    Ok(Ok(_outcome)) => {
                        if let Some(metrics) = &metrics {
                            metrics
                                .fanout_healthy
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .fanout_successes
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        completed.push(key);
                    }
                    Ok(Err(error)) => {
                        if let Some(metrics) = &metrics {
                            metrics
                                .fanout_healthy
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .fanout_failures
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        eprintln!(
                            "control-plane-api fanout deferred: {}: {}",
                            error.code.public_code(),
                            error.summary
                        );
                        failed.push(key);
                    }
                    Err(_) => {
                        if let Some(metrics) = &metrics {
                            metrics
                                .fanout_healthy
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .fanout_failures
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        eprintln!("control-plane-api fanout deferred: panic during publish");
                        failed.push(key);
                    }
                }
            }
            if !completed.is_empty() {
                let settle_result = backend
                    .with_lock_from_async(|outbox| outbox.mark_complete_many(&completed));
                if settle_result.is_err() {
                    if let Some(metrics) = &metrics {
                        metrics
                            .storage_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .outbox_write_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    eprintln!("control-plane-api: failed to settle completed fanout rows");
                    failed.extend(completed);
                } else {
                    for key in &completed {
                        failures.remove(key);
                        not_before.remove(key);
                    }
                }
            }
            if !failed.is_empty() {
                let mut retry_groups: HashMap<Duration, Vec<OutboxKey>> = HashMap::new();
                let mut quarantine = Vec::new();
                for key in failed {
                    let attempts = failures
                        .entry(key.clone())
                        .or_default();
                    *attempts = attempts.saturating_add(1);
                    if *attempts >= MAX_REPLAY_ATTEMPTS {
                        quarantine.push(key);
                        continue;
                    }
                    let delay = retry_delay(&key, *attempts);
                    not_before.insert(key.clone(), tokio::time::Instant::now() + delay);
                    retry_groups.entry(delay).or_default().push(key);
                }
                for (delay, keys) in retry_groups {
                    if backend.reschedule(&keys, delay).is_err()
                        && let Some(metrics) = &metrics
                    {
                        metrics
                            .storage_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .outbox_write_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                if !quarantine.is_empty() {
                    if backend.quarantine(&quarantine, "replay_attempts_exhausted").is_ok() {
                        if let Some(metrics) = &metrics {
                            metrics
                                .quarantined_rows
                                .fetch_add(quarantine.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        }
                        for key in quarantine {
                            failures.remove(&key);
                            not_before.remove(&key);
                        }
                    } else if let Some(metrics) = &metrics {
                        metrics
                            .storage_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                wait_for_tick = true;
            } else {
                // A full successful batch means there may be more work. Drain
                // it immediately rather than adding one configured tick of
                // latency per batch during a backlog.
                wait_for_tick = !was_full_batch;
            }
            if draining {
                break;
            }
        }
    })
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use apex_event_ingest::{GatewayError, InMemoryOutbox};

    use super::*;

    struct FlakyPublisher {
        fail_next: bool,
        published: Vec<String>,
    }

    impl EventPublisher for FlakyPublisher {
        fn publish(
            &mut self,
            event: &apex_event_ingest::IngestRequest,
        ) -> Result<apex_event_ingest::PublishOutcome, GatewayError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(GatewayError::publish_failed());
            }
            self.published.push(event.event_id().to_owned());
            Ok(apex_event_ingest::PublishOutcome::Published)
        }
    }

    /// Moves the paused virtual clock past exactly one worker tick, then
    /// yields repeatedly so the now-runnable worker task actually executes
    /// its tick (lock acquisition and the publish call are real await
    /// points, not resolved by the clock jump alone) before the caller
    /// inspects shared state.
    ///
    /// A real-time `sleep` here would reintroduce the exact race this
    /// rewrite exists to remove: `advance` and `yield_now` only move the
    /// deterministic paused clock and the task scheduler, never the wall
    /// clock, so this is not a timing guess at any margin.
    async fn advance_past_one_tick(interval: Duration) {
        // Yield first: a freshly spawned/just-resumed worker task has not
        // necessarily been polled yet, so it may not have registered its
        // `sleep(interval)` timer at the current instant. Advancing the
        // clock before that registration would jump time forward without
        // ever expiring the timer the worker is about to create. Yielding
        // guarantees at least one poll -- and thus timer registration --
        // happens before the clock moves.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(interval).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    /// An outbox whose every operation drives its own tokio runtime, exactly
    /// the way `postgres::Client` does under `PostgresOutbox`. Delegates the
    /// actual storage to `InMemoryOutbox` so only the blocking behaviour is
    /// being simulated.
    struct BlockingOutbox {
        inner: InMemoryOutbox,
    }

    impl BlockingOutbox {
        /// The exact shape of `postgres::Connection`'s internals: an owned
        /// runtime, blocked on from a synchronous method. This panics with
        /// "Cannot start a runtime from within a runtime" if the caller is a
        /// tokio worker thread that has not entered a blocking region.
        fn block(&self) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("test runtime");
            runtime.block_on(async {});
        }
    }

    impl apex_event_ingest::EventOutbox for BlockingOutbox {
        fn enqueue(
            &mut self,
            event: &apex_event_ingest::IngestRequest,
        ) -> Result<apex_event_ingest::EnqueueResult, GatewayError> {
            self.block();
            self.inner.enqueue(event)
        }

        fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
            self.block();
            self.inner.mark_complete(key)
        }

        fn pending(&mut self) -> Vec<apex_event_ingest::IngestRequest> {
            self.block();
            self.inner.pending()
        }
    }

    /// Regression test for a fault that every in-process test missed and that
    /// only appeared on the first real Postgres-backed container start: the
    /// worker called the outbox directly from its async task, and
    /// `PostgresOutbox` blocks on an internal runtime for every query, so the
    /// worker task aborted on its first tick. The process stayed up and kept
    /// accepting commands, so the container looked healthy while nothing was
    /// ever delivered again -- the same silent failure mode as never having
    /// wired the worker in at all.
    ///
    /// Multi-threaded on purpose: the flavor is the whole point, and the
    /// paused-clock test below runs on the default current-thread runtime
    /// where this hazard cannot occur.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fanout_worker_survives_an_outbox_that_blocks_on_its_own_runtime() {
        let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> = Box::new(BlockingOutbox {
            inner: InMemoryOutbox::new(16).unwrap(),
        });
        let backend = Arc::new(ControlOutboxBackend::new(outbox));
        let request = apex_event_ingest::IngestRequest::new(
            "018f0000-0000-7000-8000-000000000000",
            "acme",
            "prod",
            vec![1, 2, 3],
        );
        // `with_lock_from_async` even in setup: this test body *is* a tokio
        // worker thread, so a direct `with_lock` would panic here for the very
        // reason the test exists.
        backend
            .with_lock_from_async(|outbox| outbox.enqueue(&request))
            .unwrap()
            .unwrap();

        let publisher = Arc::new(tokio::sync::Mutex::new(FlakyPublisher {
            fail_next: false,
            published: vec![],
        }));
        let _handle = spawn_fanout_worker(
            backend.clone(),
            publisher.clone(),
            Duration::from_millis(20),
        );

        // Real time, not the paused clock: `block_in_place` moves work between
        // real threads, so a virtual clock would prove nothing here. The
        // window is generous because the assertion is "it ran at all", not
        // "it ran within N ms".
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if !publisher.lock().await.published.is_empty() {
                break;
            }
        }
        assert_eq!(
            publisher.lock().await.published.len(),
            1,
            "the worker must survive a blocking outbox instead of aborting on its first tick"
        );
        let remaining = backend
            .with_lock_from_async(|outbox| outbox.pending())
            .unwrap();
        assert!(remaining.is_empty(), "the row must still be marked complete");
    }

    #[tokio::test(start_paused = true)]
    async fn fanout_worker_retries_after_a_transient_publish_failure() {
        let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> =
            Box::new(InMemoryOutbox::new(16).unwrap());
        let backend = Arc::new(ControlOutboxBackend::new(outbox));
        let request = apex_event_ingest::IngestRequest::new(
            "018f0000-0000-7000-8000-000000000000",
            "acme",
            "prod",
            vec![1, 2, 3],
        );
        backend
            .with_lock(|outbox| outbox.enqueue(&request))
            .unwrap()
            .unwrap();

        let publisher = Arc::new(tokio::sync::Mutex::new(FlakyPublisher {
            fail_next: true,
            published: vec![],
        }));
        let interval = Duration::from_millis(5);
        let _handle = spawn_fanout_worker(backend.clone(), publisher.clone(), interval);

        // First tick: publish fails, row stays pending.
        advance_past_one_tick(interval).await;
        assert!(publisher.lock().await.published.is_empty());

        // The first failed attempt gets the per-event 2x backoff. Move the
        // paused clock past that durable retry deadline and the next worker
        // tick; this asserts the scheduler rather than relying on wall time.
        tokio::time::advance(MIN_RETRY_DELAY * 2 + Duration::from_secs(1) + interval).await;
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher.lock().await.published.len(), 1);
        let remaining = backend.with_lock(|outbox| outbox.pending()).unwrap();
        assert!(remaining.is_empty());
    }
}
