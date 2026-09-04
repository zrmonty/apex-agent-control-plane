#![cfg(feature = "postgres")]
// Required database integration suite: absence of its dedicated database fails.
#[path = "proxy_operation_recovery/relay_abort.rs"]
mod relay_abort;
#[path = "proxy_operation_recovery/relay_bounds.rs"]
mod relay_bounds;
#[path = "proxy_operation_recovery/startup_abort.rs"]
mod startup_abort;
#[path = "proxy_operation_recovery/support.rs"]
mod support;
#[path = "proxy_operation_recovery/worker_deadlines.rs"]
mod worker_deadlines;

use apex_control_plane_api::{ControlOutboxBackend, PostgresProxyStore, RecoveringPostgresOutbox};
use apex_durability::{IngestRequest, proto::EventEnvelope};
use prost::Message;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;
use support::*;

#[test]
fn recovery_child() {
    if std::env::var("APEX_PROXY_RECOVERY_CHILD").as_deref() != Ok("submit") {
        return;
    }
    let url = std::env::var("APEX_PROXY_RECOVERY_CHILD_URL").unwrap();
    let input = submission();
    let store = PostgresProxyStore::connect(&url).unwrap();
    let operation = store.submit_proxy_operation(&input).unwrap();
    println!("\nCOMMITTED {}", operation.operation_id);
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn process_death_after_commit_preserves_operation_and_replays_uncertain_enqueue_once() {
    let database = Database::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        // Keep the serial libtest framing covered even in a parallel parent suite.
        .args([
            "--exact",
            "recovery_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("APEX_PROXY_RECOVERY_CHILD", "submit")
        .env("APEX_PROXY_RECOVERY_CHILD_URL", &database.url)
        .env("APEX_ALLOW_POSTGRES_PLAINTEXT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut transcript = Vec::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let remaining = 4096 - transcript.len();
            transcript.extend(line.bytes().chain(std::iter::once(b'\n')).take(remaining));
            if let Some(id) = line.strip_prefix("COMMITTED ") {
                let _ = sender.send(id.to_owned());
                break;
            }
        }
        transcript
    });
    let observed = receiver.recv_timeout(Duration::from_secs(20));
    // Kill at the durable-commit/before-relay boundary; no graceful service exit.
    let _ = child.kill();
    let child_status = child.wait().unwrap();
    let transcript = reader.join().unwrap();
    let operation_id = observed.unwrap_or_else(|error| {
        panic!(
            "child did not commit before 20s deadline: {error}; exit={child_status}; \
             stdout (first 4096 bytes)={:?}",
            String::from_utf8_lossy(&transcript),
        )
    });

    let input = submission();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    let accepted = store
        .get_proxy_operation(&input.scope, &input.proxy_id, &operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(accepted, store.submit_proxy_operation(&input).unwrap());
    let mut client = database.client();
    let row = client.query_one(
        "SELECT canonical_payload, payload_hash FROM mcp_proxy_evidence_intents WHERE operation_id=$1",
        &[&operation_id.parse::<uuid::Uuid>().unwrap()],
    ).unwrap();
    let original: Vec<u8> = row.get(0);
    let envelope = EventEnvelope::decode(original.as_slice()).unwrap();
    assert_eq!(envelope.timestamp, "2024-05-03T12:34:56.123456Z");
    let request = IngestRequest::from_validated_transport(envelope.clone()).unwrap();
    let outbox = ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    ));
    // Simulate relay death after durable enqueue but before intent acknowledgement.
    apex_control_plane_api::submit_command(&outbox, &request).unwrap();
    drop(outbox);
    let recovered = ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    ));
    assert_eq!(
        store
            .relay_proxy_evidence(&input.scope, &input.proxy_id, &recovered, 16)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .relay_proxy_evidence(&input.scope, &input.proxy_id, &recovered, 16)
            .unwrap(),
        0
    );
    let pending = recovered.pending_batch(16).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelope, original);
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM mcp_proxy_operations WHERE request_id=$1",
            &[&input.request_id.parse::<uuid::Uuid>().unwrap()],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}

#[test]
fn competing_database_connections_obtain_only_one_live_controller_lease() {
    let database = Database::new();
    let input = submission();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    store.submit_proxy_operation(&input).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = ["controller-a", "controller-b"]
        .into_iter()
        .map(|worker| {
            let url = database.url.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = PostgresProxyStore::connect(&url).unwrap();
                let input = submission();
                barrier.wait();
                store
                    .lease_proxy_operation(
                        &input.scope,
                        &input.proxy_id,
                        worker,
                        Duration::from_secs(30),
                    )
                    .unwrap()
            })
        })
        .collect();
    let leases: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].fencing_token, 1);
}

#[test]
fn startup_relay_drains_committed_intents_without_a_client_retry_or_downstream() {
    use apex_control_plane_api::{
        GatewayShutdown, ProxyEvidenceRelayStatus, spawn_proxy_evidence_relay,
    };
    use std::sync::atomic::Ordering;

    let database = Database::new();
    let input = submission();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    store.submit_proxy_operation(&input).unwrap();
    drop(store);
    let store = Arc::new(PostgresProxyStore::connect(&database.url).unwrap());
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    )));
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let shutdown = GatewayShutdown::default();
        let handle = spawn_proxy_evidence_relay(
            Arc::clone(&store),
            Arc::clone(&outbox),
            Arc::clone(&status),
            shutdown.clone(),
        );
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            while status.relayed_events.load(Ordering::Acquire) != 1
                || !status.healthy.load(Ordering::Acquire)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        shutdown.request();
        handle.await.unwrap();
        result.expect("background relay did not recover the committed intent");
    });
    assert_eq!(status.failed_batches.load(Ordering::Acquire), 0);
    assert_eq!(outbox.pending_batch(16).unwrap().len(), 1);
    assert!(
        !status.healthy.load(Ordering::Acquire),
        "stopped worker cannot be healthy"
    );
    let rows: i64 = database
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(rows, 0);
}

#[test]
fn relay_failure_does_not_starve_later_pages_or_report_a_successful_sweep() {
    use apex_control_plane_api::{
        GatewayShutdown, ProxyEvidenceRelayStatus, spawn_proxy_evidence_relay,
    };
    use std::sync::atomic::Ordering;

    let database = Database::new();
    let store = Arc::new(PostgresProxyStore::connect(&database.url).unwrap());
    let first = submission();
    store.submit_proxy_operation(&first).unwrap();
    for _ in 0..9 {
        let input = another_submission();
        database.seed(&input);
        store.submit_proxy_operation(&input).unwrap();
    }
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    )));
    // An existing, conflicting outbox identity makes the first proxy fail closed.
    // It sorts ahead of nine later proxies, so successful work spans two pages.
    let mut conflicting = first.evidence.clone();
    conflicting.timestamp = "2024-05-03T12:34:56.654321Z".into();
    conflicting.integrity.as_mut().unwrap().event_hash =
        apex_durability::canonical_event_hash(&conflicting).unwrap();
    apex_control_plane_api::submit_command(
        &outbox,
        &IngestRequest::from_validated_transport(conflicting).unwrap(),
    )
    .unwrap();
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let shutdown = GatewayShutdown::default();
        let handle = spawn_proxy_evidence_relay(
            Arc::clone(&store),
            Arc::clone(&outbox),
            Arc::clone(&status),
            shutdown.clone(),
        );
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            // Seeing two failures proves a complete sweep and retry occurred.
            while status.relayed_events.load(Ordering::Acquire) != 9
                || status.failed_batches.load(Ordering::Acquire) < 2
            {
                assert!(!status.healthy.load(Ordering::Acquire));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(!status.healthy.load(Ordering::Acquire));
        shutdown.request();
        handle.await.unwrap();
        result.expect("a failed proxy starved later pending evidence");
    });
    let rows: i64 = database
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        rows, 1,
        "failed evidence must remain pending, never silently marked enqueued"
    );
    assert_eq!(outbox.pending_batch(16).unwrap().len(), 10);
}

#[test]
fn pre_requested_shutdown_leaves_intents_pending_and_releases_last_store_off_runtime() {
    use apex_control_plane_api::{
        GatewayShutdown, ProxyEvidenceRelayStatus, spawn_proxy_evidence_relay,
    };
    use std::sync::atomic::Ordering;
    let database = Database::new();
    let store = Arc::new(PostgresProxyStore::connect(&database.url).unwrap());
    store.submit_proxy_operation(&submission()).unwrap();
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    )));
    let shutdown = GatewayShutdown::default();
    shutdown.request();
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            spawn_proxy_evidence_relay(store, outbox, Arc::clone(&status), shutdown)
                .await
                .unwrap();
        });
    assert_eq!(status.relayed_events.load(Ordering::Acquire), 0);
    assert!(!status.healthy.load(Ordering::Acquire));
    let rows: i64 = database
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);
}

#[test]
fn relay_recovers_after_its_database_connection_is_lost_without_client_retry() {
    use apex_control_plane_api::{
        GatewayShutdown, ProxyEvidenceRelayStatus, spawn_proxy_evidence_relay,
    };
    use std::sync::atomic::Ordering;
    let database = Database::new();
    let application = format!("owned_proxy_relay_{}", uuid::Uuid::now_v7().simple());
    let store = Arc::new(
        PostgresProxyStore::connect(&format!("{}&application_name={application}", database.url))
            .unwrap(),
    );
    store.submit_proxy_operation(&submission()).unwrap();
    let mut admin = database.client();
    let pids = admin
        .query(
            "SELECT pid FROM pg_stat_activity WHERE application_name=$1",
            &[&application],
        )
        .unwrap();
    assert_eq!(
        pids.len(),
        1,
        "only terminate the uniquely named test-owned connection"
    );
    let pid: i32 = pids[0].get(0);
    let terminated: bool = admin
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .unwrap()
        .get(0);
    assert!(terminated);
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&database.url, 100).unwrap(),
    )));
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let shutdown = GatewayShutdown::default();
            let handle = spawn_proxy_evidence_relay(
                Arc::clone(&store),
                Arc::clone(&outbox),
                Arc::clone(&status),
                shutdown.clone(),
            );
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                while status.relayed_events.load(Ordering::Acquire) != 1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            shutdown.request();
            handle.await.unwrap();
            result.expect("relay never recovered a closed database connection");
        });
    assert_eq!(outbox.pending_batch(16).unwrap().len(), 1);
}
