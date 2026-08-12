//! Exactly-once across a **hard kill of the gateway process itself**, timed to
//! land deterministically inside a single in-flight fanout.
//!
//! `torn_write.rs` breaks the sinks. It never breaks the gateway. Those are
//! different failure modes: a sink outage lets the gateway observe the failure
//! and run its own error path, while `SIGKILL` gives it no error path at all.
//! The window that matters is between the durable outbox commit and the
//! downstream write -- the process dies holding an obligation nothing has
//! recorded as discharged.
//!
//! This file covers the deterministic window: the archive sink is held down,
//! so the fanout is guaranteed to still be mid-flight when the gateway is
//! killed. `gateway_kill_volley.rs` covers the windows that cannot be timed by
//! hand, under a concurrent load stream.
//!
//! Two properties, asserted against the live stores after recovery:
//!
//!   * **No lost row.** An event whose Pending outbox record was fsynced before
//!     the kill must be durable in every sink once the gateway restarts.
//!   * **No duplicate row, and no stranded Pending.** Replay must converge to
//!     exactly one copy, and must not leave an outbox entry that can never
//!     drain.
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
//!   cargo test --test gateway_kill_deterministic --features test-support -- --test-threads=1
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
    // These tests kill containers. A previous failure can leave the stack half
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

fn stop(container: &str) {
    assert!(
        docker_ok(&["stop", "-t", "2", container]),
        "could not stop {container}"
    );
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

fn clickhouse_rows(event_id: &str) -> u32 {
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/events.sqlite3');\
         print(db.execute('select count(*) from events where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&ch_container(), &script)
        .and_then(|v| v.parse().ok())
        .expect("clickhouse projection query")
}

fn archive_objects(event_id: &str) -> u32 {
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/objects.sqlite3');\
         print(db.execute('select count(*) from objects where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&archive_container(), &script)
        .and_then(|v| v.parse().ok())
        .expect("archive provider query")
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

fn journal_lines(file: &str, event_id: &str) -> Vec<String> {
    journal(file)
        .lines()
        .filter(|line| line.contains(event_id))
        .map(str::to_owned)
        .collect()
}

/// An outbox key is stranded when a `pending` record was written and no
/// `complete` record for the same key ever followed. That row can never drain:
/// startup replay is the only thing that reads it, and if it is still pending
/// after a completed restart, nothing else will ever pick it up.
fn stranded_pending(event_id: &str) -> bool {
    let lines = journal_lines("outbox.jsonl", event_id);
    let pending = lines.iter().any(|l| l.contains("\"op\":\"pending\""));
    let complete = lines.iter().any(|l| l.contains("\"op\":\"complete\""));
    pending && !complete
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

async fn channel() -> Channel {
    try_channel().await.expect("gateway channel")
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

fn converge(event_id: &str, seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if clickhouse_rows(event_id) == 1 && archive_objects(event_id) == 1 {
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// The deterministic window: the archive is down, so once the dedicated
/// fanout worker picks the row up, its delivery is guaranteed to be stuck
/// retrying against the archive (JetStream published, ClickHouse written)
/// when the gateway is SIGKILLed. Admission itself (Phase 0.6: durable
/// enqueue only, decoupled from fanout) returns almost immediately
/// regardless of archive health -- the Pending outbox record is fsynced by
/// the `send` call below; nothing has marked it complete yet either way.
///
/// After restart the event must be durable exactly once and the outbox row
/// must be settled.
#[test]
fn sigkill_between_outbox_commit_and_fanout_completion_is_exactly_once() {
    if skip("sigkill_between_outbox_commit_and_fanout_completion_is_exactly_once") {
        return;
    }
    let id = event_id(1);

    stop(&archive_container());

    // Submit in the background: the call blocks on the archive retry ladder,
    // which is the window we want to kill inside.
    let submit_id = id.clone();
    let submitter = std::thread::spawn(move || {
        runtime().block_on(async {
            let channel = channel().await;
            send(&channel, sign(base(&submit_id))).await.map(|_| ())
        })
    });

    // Let the gateway get past enqueue + JetStream + ClickHouse and into the
    // archive retries before pulling the plug.
    std::thread::sleep(Duration::from_secs(3));
    kill_gateway();
    let _ = submitter.join();

    // Restore the sink first so replay can actually complete on startup.
    start_sink(&archive_container());
    start_gateway();

    converge(&id, 120);

    assert_eq!(
        clickhouse_rows(&id),
        1,
        "a SIGKILL mid-fanout produced {} ClickHouse rows; exactly-once was violated",
        clickhouse_rows(&id)
    );
    assert_eq!(
        archive_objects(&id),
        1,
        "a SIGKILL mid-fanout produced {} archive objects; exactly-once was violated",
        archive_objects(&id)
    );
    assert!(
        !stranded_pending(&id),
        "the outbox row is still pending after recovery and can never drain: {:?}",
        journal_lines("outbox.jsonl", &id)
    );

    // Re-submitting the identical event must not fan out a second time.
    let response = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    assert!(
        response.is_ok(),
        "an identical replay after recovery must not be rejected: {response:?}"
    );
    assert_eq!(clickhouse_rows(&id), 1, "post-recovery replay duplicated the ClickHouse row");
    assert_eq!(archive_objects(&id), 1, "post-recovery replay duplicated the archive object");
}
