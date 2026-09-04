//! Recover committed evidence without client retries. Runtime reconciliation is
//! separate: this worker can enqueue evidence, never provision or admit calls.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::PostgresProxyStore;
use crate::{ControlOutboxBackend, GatewayShutdown};

#[derive(Default)]
pub struct ProxyEvidenceRelayStatus {
    /// True only after a complete successful sweep; false before startup/after
    /// shutdown. A successful later page cannot hide an earlier failure.
    pub healthy: AtomicBool,
    pub relayed_events: AtomicU64,
    pub failed_batches: AtomicU64,
}

pub fn spawn_proxy_evidence_relay(
    store: Arc<PostgresProxyStore>,
    outbox: Arc<ControlOutboxBackend>,
    status: Arc<ProxyEvidenceRelayStatus>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    let aborted = Arc::new(AtomicBool::new(false));
    // Construct before spawning: abort-before-first-poll also cancels the worker.
    let stop = StopOnDrop {
        aborted: Arc::clone(&aborted),
        status: Arc::clone(&status),
    };
    let worker_status = Arc::clone(&status);
    // Exactly one blocking job owns ALL synchronous resources for its lifetime.
    // Aborting the async supervisor cannot drop a postgres client on Tokio or
    // launch replacements while old work runs. Cancellation is checked between
    // operations; underlying database calls use the worker transport policy.
    let worker = tokio::task::spawn_blocking(move || {
        run_relay(store, outbox, worker_status, shutdown, aborted);
    });
    tokio::spawn(async move {
        let _stop = stop;
        if worker.await.is_err() {
            mark_failure(&status);
        }
    })
}

struct StopOnDrop {
    aborted: Arc<AtomicBool>,
    status: Arc<ProxyEvidenceRelayStatus>,
}
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.aborted.store(true, Ordering::Release);
        self.status.healthy.store(false, Ordering::Release);
    }
}

fn run_relay(
    store: Arc<PostgresProxyStore>,
    outbox: Arc<ControlOutboxBackend>,
    status: Arc<ProxyEvidenceRelayStatus>,
    shutdown: GatewayShutdown,
    aborted: Arc<AtomicBool>,
) {
    let stopped = || shutdown.is_requested() || aborted.load(Ordering::Acquire);
    let mut cursor = None;
    let mut sweep_failed = false;
    let mut consecutive_errors = 0_u32;
    while !stopped() {
        // Never leave a prior success healthy while new storage work stalls.
        status.healthy.store(false, Ordering::Release);
        match store.pending_proxy_evidence_targets(cursor.as_ref()) {
            Ok(targets) => {
                consecutive_errors = 0;
                let mut failed = false;
                for target in &targets {
                    if stopped() {
                        break;
                    }
                    match store.relay_proxy_evidence_cancellable(
                        &target.scope,
                        &target.proxy_id,
                        &outbox,
                        16,
                        stopped,
                    ) {
                        Ok(count) => {
                            status
                                .relayed_events
                                .fetch_add(count as u64, Ordering::Release);
                        }
                        Err(_) => failed = true,
                    }
                }
                // Advance on failure so one poison proxy cannot starve later
                // scopes. Its immutable intent remains pending for the next sweep.
                cursor = targets.into_iter().last();
                sweep_failed |= failed;
                if failed {
                    mark_failure(&status);
                }
                if cursor.is_none() && !stopped() {
                    status.healthy.store(!sweep_failed, Ordering::Release);
                    sweep_failed = false;
                }
            }
            Err(_) => {
                mark_failure(&status);
                sweep_failed = true;
                consecutive_errors = (consecutive_errors + 1).min(4);
            }
        }
        // Bounded reconnect backoff, interruptible within 50ms while idle.
        let until = Instant::now() + Duration::from_millis(250 * (1 << consecutive_errors));
        while !stopped() && Instant::now() < until {
            std::thread::sleep(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50)),
            );
        }
    }
    status.healthy.store(false, Ordering::Release);
    // store/outbox last owners drop here, exclusively on the blocking thread.
}

fn mark_failure(status: &ProxyEvidenceRelayStatus) {
    status.healthy.store(false, Ordering::Release);
    status.failed_batches.fetch_add(1, Ordering::Release);
    eprintln!("control-plane-api: proxy evidence relay unavailable; committed intents retained");
}
