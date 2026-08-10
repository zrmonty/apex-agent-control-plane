//! Exactly-once across a **hard kill of the gateway process itself**, under a
//! sustained concurrent load stream.
//!
//! `torn_write.rs` breaks the sinks. It never breaks the gateway. Those are
//! different failure modes: a sink outage lets the gateway observe the failure
//! and run its own error path, while `SIGKILL` gives it no error path at all.
//!
//! `gateway_kill_deterministic.rs` covers the one window that can be timed by
//! hand (archive down, kill mid-retry). This file covers the windows that
//! cannot -- notably "fanout fully succeeded, `mark_complete` not yet
//! written", where a naive replay would fan the event out a second time -- by
//! killing mid-volley with every sink healthy. For every id in the stream the
//! outcome must be all-or-nothing and never doubled.
//!
//! The journals live in a container volume, so they are read with `docker exec`
//! rather than from the host filesystem.
//!
//! ```text
//! APEX_KILL_GATEWAY=1 \
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_KILL_GATEWAY_CONTAINER=apex-pentest-gw-ingest-gateway-1 \
//! APEX_TORN_CH_CONTAINER=apex-pentest-gw-clickhouse-projection-1 \
//! APEX_TORN_ARCHIVE_CONTAINER=apex-pentest-gw-archive-provider-1 \
//!   cargo test --test gateway_kill_volley --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use apex_event_ingest::{canonical_event_hash, proto};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const AGENT_ID: &str = "reference-agent";

fn enabled() -> bool {
    std::env::var("APEX_KILL_GATEWAY").ok().as_deref() == Some("1")
        && std::env::var("APEX_ADVERSARIAL_GATEWAY").is_ok()
}

fn skip(name: &str) -> bool {
    if !enabled() {
        eprintln!("skip {name}: set APEX_KILL_GATEWAY=1 and APEX_ADVERSARIAL_GATEWAY");
        return true;
    }
    // This test kills containers. A previous failure can leave the stack half
    // down, which would make every later test fail for the wrong reason and
    // hide the result being measured.
    ensure_running(&ch_container());
    ensure_running(&archive_container());
    ensure_gateway_running();
    false
}

fn is_running(container: &str) -> bool {
    docker_output(&["inspect", "-f", "{{.State.Running}}", container]).as_deref() == Some("true")
}

fn ensure_running(container: &str) {
    if !is_running(container) {
        eprintln!("setup: restarting {container}");
        start_sink(container);
    }
}

fn ensure_gateway_running() {
    if !is_running(&gateway_container()) {
        eprintln!("setup: restarting {}", gateway_container());
        start_gateway();
    }
}

fn secrets_dir() -> PathBuf {
    std::env::var("APEX_ADVERSARIAL_SECRETS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/compose/live-mtls/secrets-host")
        })
}

fn gateway_container() -> String {
    std::env::var("APEX_KILL_GATEWAY_CONTAINER")
        .unwrap_or_else(|_| "apex-pentest-gw-ingest-gateway-1".to_owned())
}

fn ch_container() -> String {
    std::env::var("APEX_TORN_CH_CONTAINER")
        .unwrap_or_else(|_| "apex-pentest-gw-clickhouse-projection-1".to_owned())
}

fn archive_container() -> String {
    std::env::var("APEX_TORN_ARCHIVE_CONTAINER")
        .unwrap_or_else(|_| "apex-pentest-gw-archive-provider-1".to_owned())
}

fn read(root: &Path, name: &str) -> Vec<u8> {
    std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("missing {name}: {e}"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Container control -- only the three containers named above are ever touched
// ---------------------------------------------------------------------------

fn docker_output(args: &[&str]) -> Option<String> {
    let output = Command::new("docker").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn docker_ok(args: &[&str]) -> bool {
    Command::new("docker")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// SIGKILL: no shutdown hook, no flush, no chance to finish a fanout. Anything
/// less would let the gateway run an orderly exit path and would not exercise
/// the window this test exists for.
fn kill_gateway() {
    let container = gateway_container();
    assert!(
        docker_ok(&["kill", "-s", "KILL", &container]),
        "could not SIGKILL {container}"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if docker_output(&["inspect", "-f", "{{.State.Running}}", &container]).as_deref()
            == Some("false")
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{container} still running after SIGKILL");
}

fn start_gateway() {
    let container = gateway_container();
    assert!(docker_ok(&["start", &container]), "could not start {container}");
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if docker_output(&["inspect", "-f", "{{.State.Running}}", &container]).as_deref()
            == Some("false")
        {
            let logs = docker_output(&["logs", "--tail", "20", &container]).unwrap_or_default();
            panic!("{container} exited on restart:\n{logs}");
        }
        if runtime().block_on(async { try_channel().await }).is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let logs = docker_output(&["logs", "--tail", "40", &container]).unwrap_or_default();
    panic!("{container} did not serve again after restart:\n{logs}");
}

fn start_sink(container: &str) {
    assert!(docker_ok(&["start", container]), "could not start {container}");
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if docker_python(container, "print('up')").is_some() {
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("{container} did not come back up");
}

fn docker_python(container: &str, script: &str) -> Option<String> {
    docker_output(&["exec", container, "python", "-c", script])
}

/// Counts for many ids in a single `docker exec`.
///
/// One probe per id costs hundreds of milliseconds; a few hundred ids across
/// two stores turns into minutes of pure round-trip time. Returns counts in the
/// same order as `ids`.
fn counts_batch(container: &str, db: &str, table: &str, ids: &[String]) -> Vec<u32> {
    let list = ids
        .iter()
        .map(|id| format!("'{id}'"))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/{db}');\
         ids=[{list}];\
         print(' '.join(str(db.execute('select count(*) from {table} where event_id=?',(i,)).fetchone()[0]) for i in ids))"
    );
    let output = docker_python(container, &script)
        .unwrap_or_else(|| panic!("batch query against {container} failed"));
    let counts: Vec<u32> = output
        .split_whitespace()
        .map(|value| value.parse().expect("count"))
        .collect();
    assert_eq!(counts.len(), ids.len(), "batch query returned the wrong arity");
    counts
}

fn clickhouse_rows_batch(ids: &[String]) -> Vec<u32> {
    counts_batch(&ch_container(), "events.sqlite3", "events", ids)
}

fn archive_objects_batch(ids: &[String]) -> Vec<u32> {
    counts_batch(&archive_container(), "objects.sqlite3", "objects", ids)
}

// ---------------------------------------------------------------------------
// Journal inspection: the outbox lives in a container volume, not on the host
// ---------------------------------------------------------------------------

fn journal(file: &str) -> String {
    docker_output(&[
        "exec",
        &gateway_container(),
        "cat",
        &format!("/var/lib/apex/{file}"),
    ])
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

async fn try_channel() -> Option<Channel> {
    let root = secrets_dir();
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&root, "ca.pem")))
        .identity(Identity::from_pem(
            read(&root, "ingest-http-client.pem"),
            read(&root, "ingest-http-client.key"),
        ))
        .domain_name("localhost");
    Channel::from_shared(std::env::var("APEX_ADVERSARIAL_GATEWAY").unwrap())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .ok()
}

fn bearer() -> String {
    String::from_utf8(read(&secrets_dir(), "ingest-bearer-token"))
        .unwrap()
        .trim()
        .to_owned()
}

async fn send(
    channel: &Channel,
    envelope: proto::EventEnvelope,
) -> Result<proto::IngestResponse, tonic::Status> {
    let mut request = tonic::Request::new(envelope);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {}", bearer()).parse().unwrap());
    proto::event_ingest_client::EventIngestClient::new(channel.clone())
        .ingest(request)
        .await
        .map(|r| r.into_inner())
}

fn base(event_id: &str) -> proto::EventEnvelope {
    let mut data = prost_types::Struct::default();
    data.fields.insert(
        "note".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("kill-probe".to_owned())),
        },
    );
    proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2026-08-06T12:00:00.000000Z".to_owned(),
        r#type: 1,
        agent_id: AGENT_ID.to_owned(),
        run_id: "run-1".to_owned(),
        parent_run_id: None,
        trace_id: "trace-1".to_owned(),
        scope: Some(proto::Scope {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_group_ids: vec![],
        }),
        actor: Some(proto::Actor {
            r#type: 2,
            id: AGENT_ID.to_owned(),
        }),
        version: Some(proto::Version {
            agent_code: "v1".to_owned(),
            prompt: "p1".to_owned(),
            model: "m1".to_owned(),
        }),
        data: Some(data),
        integrity: Some(proto::Integrity {
            prev_hash: None,
            event_hash: "0".repeat(64),
        }),
        schema_version: 1,
    }
}

fn sign(mut envelope: proto::EventEnvelope) -> proto::EventEnvelope {
    let hash = canonical_event_hash(&envelope).expect("hash");
    envelope.integrity.as_mut().unwrap().event_hash = hash;
    envelope
}

fn event_id(suffix: u32) -> String {
    static NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let nonce = *NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|e| e.as_secs() % 0x0000_0000_ffff)
            .unwrap_or(0)
    });
    format!(
        "018f5c91-2d88-7c00-8000-{:012x}",
        (nonce << 24) | 0x00ee_0000 | u64::from(suffix)
    )
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// A kill with every sink healthy, in the middle of a sustained load stream.
///
/// This covers the windows the deterministic case cannot time by hand --
/// notably "fanout fully succeeded, `mark_complete` not yet written", where a
/// naive replay would fan the event out a second time. For every id in the
/// stream the outcome must be all-or-nothing and never doubled.
///
/// The sender behaves like a correct client rather than a thundering herd.
/// `AuthenticatedGrpcService` takes the adapter mutex with `try_lock` and
/// answers `ADMISSION_BUSY` (gRPC `RESOURCE_EXHAUSTED`, retryable) instead of
/// queueing, so effective ingest concurrency is one. A client that fires N
/// requests at once and never retries simply loses N-1 of them to
/// back-pressure, which would leave this test asserting almost nothing.
#[test]
fn sigkill_during_a_concurrent_volley_never_duplicates_or_strands() {
    if skip("sigkill_during_a_concurrent_volley_never_duplicates_or_strands") {
        return;
    }
    const VOLLEY: u32 = 200;
    let ids: Vec<String> = (0..VOLLEY).map(|index| event_id(100 + index)).collect();

    // Progress is published in-process. A `docker exec` probe costs hundreds of
    // milliseconds and the gateway completes this whole stream in well under
    // that, so any out-of-band check reacts long after the load has finished
    // and the kill lands after the stream instead of inside it.
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let sender_progress = progress.clone();
    let volley_ids = ids.clone();
    let sender = std::thread::spawn(move || {
        runtime().block_on(async {
            let Some(channel) = try_channel().await else {
                return 0;
            };
            let mut accepted = 0;
            for id in volley_ids {
                // Bounded retry on back-pressure only. Any other error, and
                // the connection error the kill itself produces, ends the run.
                for _ in 0..40 {
                    match send(&channel, sign(base(&id))).await {
                        Ok(_) => {
                            accepted += 1;
                            sender_progress
                                .store(accepted, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                        Err(status)
                            if status.code() == tonic::Code::ResourceExhausted =>
                        {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                        Err(_) => return accepted,
                    }
                }
            }
            accepted
        })
    });

    // Kill on observed progress, not on a timer. `AuthenticatedGrpcService`
    // serialises ingest behind one adapter mutex and each request costs a
    // JetStream ack plus two mTLS round trips, so wall-clock timing is not a
    // reliable way to land the kill mid-volley on an arbitrary machine.
    // Waiting until part of the volley is durable guarantees the process dies
    // with the rest still in flight or unstarted.
    let kill_at: u32 = std::env::var("APEX_KILL_AFTER_LANDED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(VOLLEY / 4);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut reached = 0;
    while Instant::now() < deadline {
        reached = progress.load(std::sync::atomic::Ordering::SeqCst);
        if reached >= kill_at {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        reached >= kill_at,
        "only {reached} of {VOLLEY} events were acknowledged before the deadline; \
         the stream never got going"
    );
    kill_gateway();
    let accepted_before_kill = sender.join().unwrap_or(0);
    eprintln!(
        "volley: {accepted_before_kill}/{VOLLEY} acknowledged before the SIGKILL \
         (kill fired at {reached})"
    );
    assert!(
        accepted_before_kill > 0,
        "the kill landed before any event was acknowledged; nothing was proven"
    );
    assert!(
        accepted_before_kill < VOLLEY,
        "the whole stream completed before the kill; the process did not die mid-flight"
    );

    start_gateway();

    // Give startup replay and the replay worker time to settle every row.
    std::thread::sleep(Duration::from_secs(20));

    let rows = clickhouse_rows_batch(&ids);
    let objects = archive_objects_batch(&ids);
    // One read of each journal, then check every id against it.
    let outbox = journal("outbox.jsonl");

    let mut landed = 0;
    for (index, id) in ids.iter().enumerate() {
        let row_count = rows[index];
        let object_count = objects[index];
        assert!(
            row_count <= 1,
            "event {id}: {row_count} ClickHouse rows after a SIGKILL; exactly-once was violated"
        );
        assert!(
            object_count <= 1,
            "event {id}: {object_count} archive objects after a SIGKILL; exactly-once was violated"
        );
        assert_eq!(
            row_count, object_count,
            "event {id}: partial landing after recovery ({row_count} rows, {object_count} objects)"
        );
        let lines: Vec<&str> = outbox.lines().filter(|line| line.contains(id)).collect();
        let pending = lines.iter().any(|l| l.contains("\"op\":\"pending\""));
        let complete = lines.iter().any(|l| l.contains("\"op\":\"complete\""));
        assert!(
            !pending || complete,
            "event {id}: outbox row still pending after recovery: {lines:?}"
        );
        landed += row_count;
    }

    // Every event the gateway acknowledged before the kill must have survived
    // it. Acknowledging an event that a restart then loses is exactly the
    // false-durability failure this whole suite exists to rule out.
    assert!(
        landed >= accepted_before_kill,
        "{accepted_before_kill} events were acknowledged but only {landed} survived the kill"
    );
    eprintln!("volley: {landed}/{VOLLEY} durable after recovery, none duplicated");
}
