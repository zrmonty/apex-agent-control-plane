//! Background tasks `run()` spawns onto the serving runtime: periodic
//! inbox/outbox retention and reconciliation, the status logger, the gRPC
//! health monitor, the loopback Prometheus endpoint, and the shutdown-signal
//! wait each is raced against.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apex_control_plane_api::{
    ControlInboxBackend, ControlOutboxBackend, GatewayRuntimeMetrics, GatewayShutdown,
    SharedEphemeralStore,
};

#[cfg(feature = "postgres")]
mod proxy_evidence;
#[cfg(feature = "postgres")]
pub(super) use proxy_evidence::spawn_proxy_evidence_worker;

const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INBOX_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const INBOX_RECONCILIATION_BATCH: usize = 256;

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(super) async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Periodically removes settled delivery state while retaining command
/// identities for the configured idempotency window. This runs independently
/// of JetStream so a broker outage cannot make the local inbox grow forever.
pub(super) fn spawn_inbox_retention_worker(
    outbox: Arc<ControlOutboxBackend>,
    inbox: Arc<ControlInboxBackend>,
    retention_millis: u64,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let outbox = Arc::clone(&outbox);
            let inbox = Arc::clone(&inbox);
            let metrics = Arc::clone(&metrics);
            let _ = tokio::task::spawn_blocking(move || {
                let now = now_unix_millis();
                let inbox_failed = inbox
                    .with_lock(|store| {
                        store.maintain(
                            now,
                            retention_millis,
                            apex_control_plane_api::DEFAULT_MAX_DELIVERY_ATTEMPTS,
                        )
                    })
                    .map_or(true, |result| result.is_err());
                // Expire the inbox tombstone first. If a process dies between
                // these two operations, a reused command_id still gets a
                // deliverable inbox record attached to the existing audit
                // event rather than an outbox row with no agent delivery.
                let outbox_failed = outbox.maintain(now, retention_millis).is_err();
                if outbox_failed || inbox_failed {
                    metrics
                        .retention_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
            .await;
        }
    })
}

/// Repairs the only non-atomic boundary left by the intentionally separate
/// outbox and inbox stores: a process can die after the authoritative outbox
/// commit but before the delivery record. Pending control events are decoded
/// back into their delivery shape and recorded idempotently. This is harmless
/// for normal submissions and closes the retry-after-timeout dependency.
pub(super) fn spawn_inbox_reconciliation_worker(
    outbox: Arc<ControlOutboxBackend>,
    inbox: Arc<ControlInboxBackend>,
    retention_millis: u64,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(INBOX_RECONCILIATION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let outbox = Arc::clone(&outbox);
            let inbox = Arc::clone(&inbox);
            let metrics = Arc::clone(&metrics);
            let _ = tokio::task::spawn_blocking(move || {
                let now = now_unix_millis();
                let since = now.saturating_sub(retention_millis);
                let Ok(mut events) = outbox.pending_reconciliation_batch(
                    INBOX_RECONCILIATION_BATCH,
                ) else {
                    metrics
                        .reconciliation_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("control-plane-api: inbox reconciliation could not read the outbox");
                    return;
                };
                let Ok(completed) = outbox.recent_completed_batch(
                    since,
                    INBOX_RECONCILIATION_BATCH,
                ) else {
                    metrics
                        .reconciliation_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "control-plane-api: completed-row reconciliation could not read the outbox"
                    );
                    return;
                };
                events.extend(completed);
                for event in events {
                    let Ok(delivery) = apex_control_plane_api::pending_command_from_ingest_request(
                        &event,
                    ) else {
                        metrics
                            .reconciliation_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        eprintln!(
                            "control-plane-api: inbox reconciliation skipped a malformed control event"
                        );
                        continue;
                    };
                    let result = inbox.with_lock(|store| store.record(&delivery));
                    match result {
                        Ok(Ok(apex_control_plane_api::RecordResult::Recorded)) => {
                            metrics
                                .reconciliation_repairs
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(Ok(apex_control_plane_api::RecordResult::AlreadyRecorded)) => {}
                        Ok(Err(_)) | Err(_) => {
                            metrics
                                .reconciliation_failures
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            eprintln!(
                                "control-plane-api: inbox reconciliation could not record a pending command"
                            );
                        }
                    }
                }
            })
            .await;
        }
    })
}

pub(super) fn spawn_status_logger(
    outbox: Arc<ControlOutboxBackend>,
    inbox: Arc<ControlInboxBackend>,
    metrics: Arc<GatewayRuntimeMetrics>,
    ephemeral: Option<SharedEphemeralStore>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let accelerator_sidelined = ephemeral.as_ref().is_some_and(|store| {
                store
                    .lock()
                    .map(|guard| guard.accelerator_sidelined())
                    .unwrap_or(true)
            });
            let outbox_for_status = Arc::clone(&outbox);
            let inbox_for_status = Arc::clone(&inbox);
            let metrics_for_status = Arc::clone(&metrics);
            let _ = tokio::task::spawn_blocking(move || {
                let counts = (
                    outbox_for_status.pending_count(),
                    outbox_for_status.quarantined_count(),
                    inbox_for_status.pending_count(),
                    inbox_for_status.undelivered_count(),
                );
                match counts {
                    (
                        Ok(outbox_pending),
                        Ok(quarantined),
                        Ok(inbox_pending),
                        Ok(inbox_undelivered),
                    ) => {
                        metrics_for_status
                            .outbox_pending
                            .store(outbox_pending, std::sync::atomic::Ordering::Relaxed);
                        metrics_for_status
                            .quarantined_current
                            .store(quarantined, std::sync::atomic::Ordering::Relaxed);
                        metrics_for_status
                            .inbox_pending
                            .store(inbox_pending, std::sync::atomic::Ordering::Relaxed);
                        metrics_for_status
                            .inbox_undelivered
                            .store(inbox_undelivered, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {
                        metrics_for_status
                            .outbox_read_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics_for_status
                            .storage_healthy
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
            .await;
            eprintln!("{}", metrics.status_line(accelerator_sidelined));
        }
    })
}

pub(super) fn spawn_health_monitor(
    reporter: tonic_health::server::HealthReporter,
    metrics: Arc<GatewayRuntimeMetrics>,
    ephemeral: Option<SharedEphemeralStore>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => {
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway.Fanout",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway.AdmissionAccelerator",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    break;
                }
            }
            let accelerator_sidelined = ephemeral.as_ref().is_some_and(|store| {
                store
                    .lock()
                    .map(|guard| guard.accelerator_sidelined())
                    .unwrap_or(true)
            });
            metrics.set_accelerator_sidelined(accelerator_sidelined);
            let storage_status = if metrics
                .storage_healthy
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            let fanout_status = if metrics
                .fanout_healthy
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            let accelerator_status = if metrics.accelerator_healthy() {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            reporter
                .set_service_status("apex.v1.ControlGateway", storage_status)
                .await;
            reporter
                .set_service_status("apex.v1.ControlGateway.Fanout", fanout_status)
                .await;
            reporter
                .set_service_status(
                    "apex.v1.ControlGateway.AdmissionAccelerator",
                    accelerator_status,
                )
                .await;
        }
    })
}

/// Serves a loopback-only Prometheus text endpoint without adding an HTTP
/// framework to the control plane. It is intentionally separate from the
/// mTLS command listener: metrics are local diagnostics, never a remote
/// control surface.
pub(super) fn spawn_metrics_server(
    addr: std::net::SocketAddr,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("apex-control-plane-api: metrics listener failed: {error}");
                return;
            }
        };
        eprintln!("apex-control-plane-api metrics listening on http://{addr}/metrics");
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue; };
                    let metrics = Arc::clone(&metrics);
                    tokio::spawn(async move {
                        serve_metrics_connection(stream, metrics).await;
                    });
                }
            }
        }
    })
}

async fn serve_metrics_connection(
    mut stream: tokio::net::TcpStream,
    metrics: Arc<GatewayRuntimeMetrics>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut request = [0_u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(0);
    let first_line = String::from_utf8_lossy(&request[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let snapshot = metrics.snapshot();
    let (status, body) = if first_line.starts_with("GET /metrics ") {
        (
            "200 OK",
            format!(
                "# TYPE apex_control_gateway_submissions_total counter\napex_control_gateway_submissions_total {}\n# TYPE apex_control_gateway_duplicate_submissions_total counter\napex_control_gateway_duplicate_submissions_total {}\n# TYPE apex_control_gateway_polls_total counter\napex_control_gateway_polls_total {}\n# TYPE apex_control_gateway_fanout_successes_total counter\napex_control_gateway_fanout_successes_total {}\n# TYPE apex_control_gateway_fanout_failures_total counter\napex_control_gateway_fanout_failures_total {}\n# TYPE apex_control_gateway_quarantined_rows_total counter\napex_control_gateway_quarantined_rows_total {}\n# TYPE apex_control_gateway_quarantined_rows gauge\napex_control_gateway_quarantined_rows {}\n# TYPE apex_control_gateway_outbox_pending gauge\napex_control_gateway_outbox_pending {}\n# TYPE apex_control_gateway_inbox_pending gauge\napex_control_gateway_inbox_pending {}\n# TYPE apex_control_gateway_inbox_undelivered gauge\napex_control_gateway_inbox_undelivered {}\n# TYPE apex_control_gateway_storage_healthy gauge\napex_control_gateway_storage_healthy {}\n# TYPE apex_control_gateway_fanout_healthy gauge\napex_control_gateway_fanout_healthy {}\n# TYPE apex_control_gateway_accelerator_configured gauge\napex_control_gateway_accelerator_configured {}\n# TYPE apex_control_gateway_accelerator_sidelined gauge\napex_control_gateway_accelerator_sidelined {}\n",
                snapshot.submissions,
                snapshot.duplicate_submissions,
                snapshot.polls,
                snapshot.fanout_successes,
                snapshot.fanout_failures,
                snapshot.quarantined_rows,
                snapshot.quarantined_current,
                snapshot.outbox_pending,
                snapshot.inbox_pending,
                snapshot.inbox_undelivered,
                u8::from(snapshot.storage_healthy),
                u8::from(snapshot.fanout_healthy),
                u8::from(snapshot.accelerator_configured),
                u8::from(snapshot.accelerator_sidelined),
            ),
        )
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };
    #[cfg(feature = "postgres")]
    let body = if status == "200 OK" {
        body + &metrics.browser_observation_prometheus()
    } else {
        body
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

#[cfg(all(test, feature = "postgres"))]
mod metrics_tests;
