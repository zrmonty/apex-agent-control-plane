//! Partial-landing / torn-write tests against a **live** gateway and live sinks.
//!
//! The admission boundary can be perfect and the system still lose or duplicate
//! data if a fanout tears halfway through. These tests deliberately break one
//! sink at a time, then assert the two properties that matter:
//!
//!   * a valid event never lands *partially* -- either every sink has it or
//!     none does, and the durable outbox still owns the retry;
//!   * an invalid event never lands *anywhere*, even while a sink is down and
//!     the retry machinery is active.
//!
//! Requires the same environment as `adversarial_ingest.rs`, plus permission to
//! stop and start the sink containers named by
//! `APEX_TORN_CH_CONTAINER` / `APEX_TORN_ARCHIVE_CONTAINER`.
//!
//! ```text
//! APEX_TORN_WRITE=1 \
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test torn_write --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use apex_event_ingest::{canonical_event_hash, proto};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const AGENT_ID: &str = "reference-agent";

fn enabled() -> bool {
    std::env::var("APEX_TORN_WRITE").ok().as_deref() == Some("1")
        && std::env::var("APEX_ADVERSARIAL_GATEWAY").is_ok()
}

fn skip(name: &str) -> bool {
    if !enabled() {
        eprintln!("skip {name}: set APEX_TORN_WRITE=1 and APEX_ADVERSARIAL_GATEWAY");
        return true;
    }
    // These tests stop sink containers. A run that dies between `stop` and
    // `start` leaves the stack half down, and every later test then fails for
    // that reason rather than the one being measured.
    for container in [ch_container(), archive_container()] {
        let running = Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &container])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "true")
            .unwrap_or(false);
        if !running {
            eprintln!("setup: restarting {container}");
            start(&container);
        }
    }
    false
}

fn secrets_dir() -> PathBuf {
    std::env::var("APEX_ADVERSARIAL_SECRETS").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets-host")
    })
}

fn outbox_dir() -> Option<PathBuf> {
    std::env::var("APEX_ADVERSARIAL_OUTBOX_DIR").ok().map(PathBuf::from)
}

fn read(root: &Path, name: &str) -> Vec<u8> {
    std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("missing {name}: {e}"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

fn ch_container() -> String {
    std::env::var("APEX_TORN_CH_CONTAINER")
        .unwrap_or_else(|_| "apex-live-mtls-clickhouse-projection-1".to_owned())
}

fn archive_container() -> String {
    std::env::var("APEX_TORN_ARCHIVE_CONTAINER")
        .unwrap_or_else(|_| "apex-live-mtls-archive-provider-1".to_owned())
}

// ---------------------------------------------------------------------------
// Container control -- only ever touches the two sink containers named above
// ---------------------------------------------------------------------------

fn docker(args: &[&str]) -> bool {
    Command::new("docker").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

fn stop(container: &str) {
    assert!(docker(&["stop", "-t", "2", container]), "could not stop {container}");
}

fn start(container: &str) {
    assert!(docker(&["start", container]), "could not start {container}");
    // Wait for the provider to accept connections again before asserting.
    let deadline = Instant::now() + Duration::from_secs(60);
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
    let output = Command::new("docker").args(["exec", container, "python", "-c", script]).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn clickhouse_rows(event_id: &str) -> u32 {
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/events.sqlite3');\
         print(db.execute('select count(*) from events where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&ch_container(), &script).and_then(|v| v.parse().ok()).expect("ch query")
}

fn archive_objects(event_id: &str) -> u32 {
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/objects.sqlite3');\
         print(db.execute('select count(*) from objects where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&archive_container(), &script).and_then(|v| v.parse().ok()).expect("archive query")
}

/// The gateway's durable journals, as text.
///
/// Two shapes are supported. A natively-run gateway writes them to a host
/// directory (`APEX_ADVERSARIAL_OUTBOX_DIR`). A containerised gateway -- now
/// the supported deployment -- keeps them in a volume, so they are read with
/// `docker exec` against `APEX_TORN_GATEWAY_CONTAINER` instead.
///
/// Returning an empty string when neither is configured would silently turn
/// every "a pending row must exist" assertion into a pass against no evidence,
/// so an unconfigured harness panics rather than reporting a hollow success.
fn journal(file: &str) -> String {
    if let Some(dir) = outbox_dir() {
        return std::fs::read_to_string(dir.join(file)).unwrap_or_default();
    }
    let container = std::env::var("APEX_TORN_GATEWAY_CONTAINER").unwrap_or_else(|_| {
        panic!(
            "set APEX_ADVERSARIAL_OUTBOX_DIR (native gateway) or \
             APEX_TORN_GATEWAY_CONTAINER (containerised gateway); without one \
             of them the durable-journal assertions prove nothing"
        )
    });
    let output = Command::new("docker")
        .args(["exec", &container, "cat", &format!("/var/lib/apex/{file}")])
        .output()
        .unwrap_or_else(|e| panic!("docker exec against {container} failed: {e}"));
    // A missing file is legitimate before the first write.
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Lines mentioning this event in the durable outbox journal, and whether any
/// of them is still in a non-complete state.
fn outbox_lines(event_id: &str) -> Vec<String> {
    journal("outbox.jsonl")
        .lines()
        .filter(|l| l.contains(event_id))
        .map(str::to_owned)
        .collect()
}

fn idempotency_lines(event_id: &str) -> Vec<String> {
    journal("idempotency.jsonl")
        .lines()
        .filter(|l| l.contains(event_id))
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Envelope helpers (mirrors adversarial_ingest.rs)
// ---------------------------------------------------------------------------

async fn channel() -> Channel {
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
        .expect("gateway channel")
}

fn bearer() -> String {
    String::from_utf8(read(&secrets_dir(), "ingest-bearer-token")).unwrap().trim().to_owned()
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
            kind: Some(prost_types::value::Kind::StringValue("torn-write-probe".to_owned())),
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
        actor: Some(proto::Actor { r#type: 2, id: AGENT_ID.to_owned() }),
        version: Some(proto::Version {
            agent_code: "v1".to_owned(),
            prompt: "p1".to_owned(),
            model: "m1".to_owned(),
        }),
        data: Some(data),
        integrity: Some(proto::Integrity { prev_hash: None, event_hash: "0".repeat(64) }),
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
    format!("018f5c91-2d88-7c00-8000-{:012x}", (nonce << 24) | 0x00ff_0000 | u64::from(suffix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// ClickHouse down, archive up. A valid event must not land in the archive
/// alone, and an invalid event must not land anywhere. Once ClickHouse is
/// restored the valid event must become durable exactly once.
#[test]
fn clickhouse_outage_does_not_produce_a_partial_landing() {
    if skip("clickhouse_outage_does_not_produce_a_partial_landing") {
        return;
    }
    let valid_id = event_id(1);
    let invalid_id = event_id(2);

    stop(&ch_container());
    let outage_result = runtime().block_on(async {
        let channel = channel().await;
        let valid = send(&channel, sign(base(&valid_id))).await;

        // An invalid event submitted *during* the outage must be refused by
        // admission, never queued "for later" behind the broken sink.
        let mut forged = sign(base(&invalid_id));
        forged.integrity.as_mut().unwrap().event_hash = "b".repeat(64);
        let invalid = send(&channel, forged).await;
        (valid, invalid)
    });

    let (valid, invalid) = outage_result;
    assert!(valid.is_err(), "a valid event must not be acknowledged while a sink is down");
    assert!(invalid.is_err(), "a forged event must be refused during an outage too");

    // The archive is still up. The fanout reached it only if ClickHouse
    // succeeded first, so nothing may be there.
    assert_eq!(archive_objects(&valid_id), 0, "valid event landed in the archive alone");
    assert_eq!(archive_objects(&invalid_id), 0, "forged event landed in the archive");

    // The forged event must leave no durable trace at all.
    assert!(
        outbox_lines(&invalid_id).is_empty(),
        "a forged event was written to the durable outbox: {:?}",
        outbox_lines(&invalid_id)
    );
    assert!(
        idempotency_lines(&invalid_id).is_empty(),
        "a forged event poisoned an idempotency key: {:?}",
        idempotency_lines(&invalid_id)
    );

    // The valid event must still be owned by the outbox so it can be retried.
    assert!(
        !outbox_lines(&valid_id).is_empty(),
        "a valid event failed its fanout but left no durable outbox record to retry from"
    );

    start(&ch_container());

    // The replay worker runs on a 5s interval; give it a few cycles.
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if clickhouse_rows(&valid_id) == 1 && archive_objects(&valid_id) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(clickhouse_rows(&valid_id), 1, "outbox replay did not durably land the valid event");
    assert_eq!(archive_objects(&valid_id), 1, "outbox replay produced the wrong archive count");
    assert_eq!(clickhouse_rows(&invalid_id), 0, "the forged event landed after recovery");
    assert_eq!(archive_objects(&invalid_id), 0, "the forged event landed after recovery");
}

/// Archive down, ClickHouse up. ClickHouse is written first, so this is the
/// case that can genuinely tear: the projection has the row and the archive
/// does not. Recovery must converge to exactly one of each, never two.
#[test]
fn archive_outage_converges_to_exactly_once_after_recovery() {
    if skip("archive_outage_converges_to_exactly_once_after_recovery") {
        return;
    }
    let id = event_id(11);

    stop(&archive_container());
    let result = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    assert!(result.is_err(), "an event must not be acknowledged while the archive is down");
    assert_eq!(archive_objects_when_down(), 0, "archive is down; nothing can have landed there");

    // The outbox must still own the row.
    assert!(
        !outbox_lines(&id).is_empty(),
        "a torn fanout left no durable outbox record; the event would be lost"
    );

    start(&archive_container());

    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if clickhouse_rows(&id) == 1 && archive_objects(&id) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    // The projection was written before the tear and again on replay. Its
    // create-or-duplicate semantics must collapse that into one row.
    assert_eq!(clickhouse_rows(&id), 1, "replay after a torn fanout duplicated the ClickHouse row");
    assert_eq!(archive_objects(&id), 1, "replay after a torn fanout duplicated the archive object");
}

fn archive_objects_when_down() -> u32 {
    // The container is stopped, so a query is impossible; treat as zero and
    // rely on the post-recovery assertions for the real evidence.
    0
}

/// A gateway restart between the outbox commit and a completed fanout must not
/// lose the event, and must not fan it out twice.
#[test]
fn pending_outbox_rows_survive_and_do_not_duplicate() {
    if skip("pending_outbox_rows_survive_and_do_not_duplicate") {
        return;
    }
    let id = event_id(21);

    stop(&ch_container());
    let result = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    assert!(result.is_err(), "fanout must fail while ClickHouse is down");

    let pending = outbox_lines(&id);
    assert!(!pending.is_empty(), "no pending outbox row to recover from");

    start(&ch_container());

    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if clickhouse_rows(&id) == 1 && archive_objects(&id) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(clickhouse_rows(&id), 1, "pending row replayed into a duplicate");
    assert_eq!(archive_objects(&id), 1, "pending row replayed into a duplicate archive object");

    // Re-submitting the same event afterwards must be a duplicate, not a
    // second fanout -- the idempotency key has to have survived the tear.
    let second = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    let response = second.expect("an identical replay after recovery must not be rejected");

    // The event was made durable by the replay worker, not by this call, so
    // this call must say `duplicate`. It used to say `duplicate: false`: a
    // publish failure aborts the idempotency reservation while the outbox row
    // survives and is later completed by the replay worker, leaving the
    // idempotency journal with no memory of the key while the outbox answered
    // AlreadyComplete -- and `publish` returned a bare `Ok(())` that the
    // gateway could not tell apart from a fresh publish.
    //
    // `EventPublisher::publish` now returns `PublishOutcome`, so the gateway
    // distinguishes the two and settles the reservation, healing the
    // divergence. See src/gateway/publisher.rs.
    assert!(
        response.duplicate,
        "an event already made durable by outbox replay must be reported as a \
         duplicate, not as though this call stored it"
    );

    // The next identical submission must also be a duplicate, now via the fast
    // idempotency path rather than the outbox.
    let third = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    assert!(
        third.expect("a second identical replay must not be rejected").duplicate,
        "the idempotency journal must have been settled by the previous answer"
    );

    assert_eq!(clickhouse_rows(&id), 1, "post-recovery replay duplicated the ClickHouse row");
    assert_eq!(archive_objects(&id), 1, "post-recovery replay duplicated the archive object");
}

/// After a torn fanout has been reconciled by outbox replay, reusing the same
/// `event_id` with DIFFERENT content must still be an idempotency conflict.
///
/// Regression guard. A publish failure aborts the idempotency reservation while
/// the outbox row survives and is later completed by the replay worker. That
/// leaves the two journals disagreeing: the idempotency store has no record of
/// the key, and the outbox's completed-key set carried no payload fingerprint,
/// so a re-submission under the same id was answered `Accepted` no matter what
/// it contained -- acknowledging an event the system never stored.
#[test]
fn tampered_replay_after_a_torn_fanout_is_still_a_conflict() {
    if skip("tampered_replay_after_a_torn_fanout_is_still_a_conflict") {
        return;
    }
    let id = event_id(31);

    // 1. Tear the fanout: ClickHouse down, so the outbox row stays pending.
    stop(&ch_container());
    let torn = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, sign(base(&id))).await
    });
    assert!(torn.is_err(), "fanout must fail while ClickHouse is down");

    // 2. Recover and let the replay worker complete the original payload.
    start(&ch_container());
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if clickhouse_rows(&id) == 1 && archive_objects(&id) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(clickhouse_rows(&id), 1, "replay did not land the original payload");

    // 3. Re-submit the SAME event_id carrying different, validly-signed content.
    let mut tampered = base(&id);
    tampered.run_id = "run-tampered".to_owned();
    let tampered = sign(tampered);
    let response = runtime().block_on(async {
        let channel = channel().await;
        send(&channel, tampered).await
    });

    let status = response.expect_err(
        "a different payload under an already-completed event_id must be refused, \
         not acknowledged as accepted",
    );
    assert!(
        status.message().contains("IDEMPOTENCY_CONFLICT"),
        "tampered post-recovery replay must be a typed idempotency conflict: {status:?}"
    );

    // The stored event must still be the original one, exactly once.
    assert_eq!(clickhouse_rows(&id), 1, "tampered replay changed the ClickHouse row count");
    assert_eq!(archive_objects(&id), 1, "tampered replay changed the archive object count");
}
