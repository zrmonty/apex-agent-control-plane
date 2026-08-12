//! Adversarial data-admission corpus against a **live** ingest gateway:
//! the happy-path baseline, hash-integrity forgery, and JCS canonicalization
//! divergence.
//!
//! Every other test in this crate exercises the gateway in-process. This one
//! speaks real gRPC over a real mTLS connection to a running
//! `apex-event-ingest`, sends malformed / forged envelopes, and then
//! **queries the downstream stores directly** to prove nothing landed.
//!
//! A typed rejection from the gateway is not, on its own, evidence. A rejected
//! request that still leaves a ClickHouse row, an archive object, a pending
//! outbox entry, or a poisoned idempotency key is a finding. Each case
//! therefore asserts the negative against every store.
//!
//! Enabled only when `APEX_ADVERSARIAL_GATEWAY` is set; skipped otherwise so
//! offline unit CI stays green. See the sibling `adversarial_*.rs` files for
//! the rest of this corpus: scope/replay, malformed payloads, and transport
//! admission.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test adversarial_integrity --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::process::Command;

use apex_event_ingest::{canonical_event_hash, proto};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const AGENT_ID: &str = "reference-agent";
const WORKSPACE: &str = "acme";
const NAMESPACE: &str = "prod";

// ---------------------------------------------------------------------------
// Environment / harness plumbing
// ---------------------------------------------------------------------------

fn gateway_endpoint() -> Option<String> {
    std::env::var("APEX_ADVERSARIAL_GATEWAY").ok().filter(|v| !v.is_empty())
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
    std::fs::read(root.join(name))
        .unwrap_or_else(|error| panic!("missing fixture {name} under {}: {error}", root.display()))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime")
}

/// mTLS channel presenting the authorized client identity.
async fn authorized_channel() -> Channel {
    let root = secrets_dir();
    client_channel(
        read(&root, "ca.pem"),
        read(&root, "ingest-http-client.pem"),
        read(&root, "ingest-http-client.key"),
    )
    .await
    .expect("authorized client must connect")
}

async fn client_channel(
    ca: Vec<u8>,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
) -> Result<Channel, tonic::transport::Error> {
    let endpoint = gateway_endpoint().expect("gateway endpoint");
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(client_cert, client_key))
        // The gateway server certificate carries SAN `localhost`.
        .domain_name("localhost");
    Channel::from_shared(endpoint)
        .expect("endpoint uri")
        .tls_config(tls)?
        .connect()
        .await
}

/// The gateway requires BOTH the pinned client certificate and a matching
/// bearer credential. Transport identity alone is not sufficient, so every
/// request in this corpus carries the token; the cases that probe credential
/// handling override it explicitly.
fn bearer_token() -> String {
    let root = secrets_dir();
    String::from_utf8(read(&root, "ingest-bearer-token"))
        .expect("bearer token is UTF-8")
        .trim()
        .to_owned()
}

fn authorized_request<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", bearer_token()).parse().expect("bearer metadata"),
    );
    request
}

async fn send_envelope(
    channel: &Channel,
    envelope: proto::EventEnvelope,
) -> Result<proto::IngestResponse, tonic::Status> {
    let mut client = proto::event_ingest_client::EventIngestClient::new(channel.clone());
    client
        .ingest(authorized_request(envelope))
        .await
        .map(|response| response.into_inner())
}

// ---------------------------------------------------------------------------
// Valid-envelope construction
// ---------------------------------------------------------------------------

fn base_envelope(event_id: &str) -> proto::EventEnvelope {
    let mut data = prost_types::Struct::default();
    data.fields.insert(
        "note".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("adversarial-probe".to_owned())),
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
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
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

/// Recomputes `integrity.event_hash` so the envelope is genuinely well-formed.
fn sign(mut envelope: proto::EventEnvelope) -> proto::EventEnvelope {
    let hash = canonical_event_hash(&envelope).expect("canonical hash");
    envelope.integrity.as_mut().expect("integrity").event_hash = hash;
    envelope
}

fn valid_envelope(event_id: &str) -> proto::EventEnvelope {
    sign(base_envelope(event_id))
}

/// Distinct UUIDv7-shaped ids so each case owns its own idempotency key.
///
/// The gateway's durable idempotency journal survives process restarts, so ids
/// must also be unique *across runs* -- otherwise a rerun would see its own
/// previous submissions as duplicates. The low 48 bits carry a per-run nonce
/// plus the case suffix; the version/variant nibbles stay fixed so the value
/// remains a valid lowercase UUIDv7.
fn event_id(suffix: u32) -> String {
    static RUN_NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let nonce = *RUN_NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() % 0x0000_0000_ffff)
            .unwrap_or(0)
    });
    format!("018f5c91-2d88-7c00-8000-{:012x}", (nonce << 24) | u64::from(suffix))
}

// ---------------------------------------------------------------------------
// Downstream store interrogation -- the "assert the negative" half
// ---------------------------------------------------------------------------

fn container(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn docker_python(container_name: &str, script: &str) -> Option<String> {
    let output = Command::new("docker")
        .args(["exec", container_name, "python", "-c", script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Rows in the reference ClickHouse projection for this event id.
fn clickhouse_rows(event_id: &str) -> u32 {
    let name = container("APEX_ADVERSARIAL_CH_CONTAINER", "apex-live-mtls-clickhouse-projection-1");
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/events.sqlite3');\
         print(db.execute('select count(*) from events where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&name, &script)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("could not query ClickHouse projection container {name}"))
}

/// Objects in the reference archive for this event id.
fn archive_objects(event_id: &str) -> u32 {
    let name = container("APEX_ADVERSARIAL_ARCHIVE_CONTAINER", "apex-live-mtls-archive-provider-1");
    let script = format!(
        "import sqlite3;db=sqlite3.connect('/var/lib/apex/objects.sqlite3');\
         print(db.execute('select count(*) from objects where event_id=?',('{event_id}',)).fetchone()[0])"
    );
    docker_python(&name, &script)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("could not query archive provider container {name}"))
}

/// Raw occurrences of the event id in the durable outbox / idempotency journals.
fn journal_hits(file: &str, event_id: &str) -> usize {
    let Some(dir) = outbox_dir() else { return 0 };
    let path = dir.join(file);
    let Ok(text) = std::fs::read_to_string(&path) else { return 0 };
    text.lines().filter(|line| line.contains(event_id)).count()
}

/// Proves an adversarial input left no trace in any durable store.
fn assert_nothing_landed(label: &str, event_id: &str) {
    assert_eq!(clickhouse_rows(event_id), 0, "{label}: a ClickHouse row landed for a rejected event");
    assert_eq!(archive_objects(event_id), 0, "{label}: an archive object landed for a rejected event");
    assert_eq!(
        journal_hits("outbox.jsonl", event_id),
        0,
        "{label}: a durable outbox entry was stranded by a rejected event"
    );
    assert_eq!(
        journal_hits("idempotency.jsonl", event_id),
        0,
        "{label}: a rejected event poisoned an idempotency key"
    );
}

/// Proves an accepted event landed exactly once everywhere.
///
/// Phase 0.6: admission durably enqueues and acknowledges independently of
/// downstream fanout, which now runs in a background worker off the admission
/// call stack. An accepted response is no longer proof that ClickHouse/archive
/// already hold the event, so this polls for the worker to catch up before
/// asserting -- and still fails informatively if the event never lands.
fn assert_landed_exactly_once(label: &str, event_id: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline
        && !(clickhouse_rows(event_id) == 1 && archive_objects(event_id) == 1)
    {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(clickhouse_rows(event_id), 1, "{label}: expected exactly one ClickHouse row");
    assert_eq!(archive_objects(event_id), 1, "{label}: expected exactly one archive object");
}

fn skip(name: &str) -> bool {
    if gateway_endpoint().is_none() {
        eprintln!("skip {name}: set APEX_ADVERSARIAL_GATEWAY to a running gateway");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 0. Baseline: the happy path must actually work, or nothing below means much
// ---------------------------------------------------------------------------

#[test]
fn valid_event_is_accepted_and_lands_exactly_once() {
    if skip("valid_event_is_accepted_and_lands_exactly_once") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;
        let id = event_id(1);
        let response = send_envelope(&channel, valid_envelope(&id)).await.expect("valid event accepted");
        assert!(!response.duplicate, "first submission must not report duplicate");
        assert_landed_exactly_once("valid baseline", &id);
    });
}

// ---------------------------------------------------------------------------
// 1. Integrity: forged, mismatched, and re-encoded hashes
// ---------------------------------------------------------------------------

#[test]
fn forged_and_mismatched_hashes_are_rejected_and_land_nowhere() {
    if skip("forged_and_mismatched_hashes_are_rejected_and_land_nowhere") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // (a) Hash of a *different* canonical form: sign one body, ship another.
        let id = event_id(10);
        let mut envelope = valid_envelope(&id);
        // Body mutated after signing -- the stored hash is now for other bytes.
        envelope.data.as_mut().unwrap().fields.insert(
            "note".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("mutated-after-signing".to_owned())),
            },
        );
        let status = send_envelope(&channel, envelope).await.expect_err("mutated body must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "mutated body: {status:?}");
        assert_nothing_landed("mutated body after signing", &id);

        // (b) Entirely forged hash (well-formed hex, wrong value).
        let id = event_id(11);
        let mut envelope = valid_envelope(&id);
        envelope.integrity.as_mut().unwrap().event_hash = "b".repeat(64);
        let status = send_envelope(&channel, envelope).await.expect_err("forged hash must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "forged hash: {status:?}");
        assert_nothing_landed("forged event_hash", &id);

        // (c) Hash borrowed from a *different but valid* envelope.
        let id = event_id(12);
        let other = valid_envelope(&event_id(13));
        let mut envelope = valid_envelope(&id);
        envelope.integrity.as_mut().unwrap().event_hash =
            other.integrity.as_ref().unwrap().event_hash.clone();
        let status = send_envelope(&channel, envelope).await.expect_err("borrowed hash must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "borrowed hash: {status:?}");
        assert_nothing_landed("hash borrowed from another event", &id);
    });
}

#[test]
fn hash_encoding_tricks_are_rejected() {
    if skip("hash_encoding_tricks_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;
        let base = valid_envelope(&event_id(20));
        let real = base.integrity.as_ref().unwrap().event_hash.clone();

        // Uppercase hex, truncated, over-long, non-hex, and empty must all fail
        // the lowercase-SHA-256 shape check before any comparison happens.
        let variants: Vec<(&str, String)> = vec![
            ("uppercase hex", real.to_uppercase()),
            ("truncated to 63", real[..63].to_owned()),
            ("padded to 65", format!("{real}0")),
            ("leading whitespace", format!(" {}", &real[1..])),
            ("non-hex characters", "g".repeat(64)),
            ("empty", String::new()),
            ("unicode digits", "١".repeat(64)),
        ];
        for (index, (label, forged)) in variants.into_iter().enumerate() {
            let id = event_id(21 + index as u32);
            let mut envelope = valid_envelope(&id);
            envelope.integrity.as_mut().unwrap().event_hash = forged;
            let status = send_envelope(&channel, envelope)
                .await
                .expect_err(&format!("{label}: must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{label}: {status:?}");
            assert_nothing_landed(label, &id);
        }
    });
}

// ---------------------------------------------------------------------------
// 2. JCS canonicalization divergence
// ---------------------------------------------------------------------------

#[test]
fn canonicalization_divergence_cannot_forge_a_valid_hash() {
    if skip("canonicalization_divergence_cannot_forge_a_valid_hash") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // Unicode normalization: NFC and NFD forms of the same grapheme are
        // different byte strings and MUST hash differently. Signing the NFC
        // form and shipping the NFD form must be caught.
        let id = event_id(40);
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert(
            "name".to_owned(),
            prost_types::Value {
                // NFC: U+00E9
                kind: Some(prost_types::value::Kind::StringValue("caf\u{e9}".to_owned())),
            },
        );
        let signed_nfc = sign(envelope.clone());
        let nfc_hash = signed_nfc.integrity.as_ref().unwrap().event_hash.clone();
        // Swap to NFD (e + combining acute) but keep the NFC hash.
        let mut nfd = envelope;
        nfd.data.as_mut().unwrap().fields.insert(
            "name".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("cafe\u{301}".to_owned())),
            },
        );
        nfd.integrity.as_mut().unwrap().event_hash = nfc_hash;
        let status = send_envelope(&channel, nfd).await.expect_err("NFD body under NFC hash must fail");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "NFC/NFD: {status:?}");
        assert_nothing_landed("NFC signed / NFD shipped", &id);

        // Float formats: 1.0 and 1 are the same IEEE double, so they are the
        // same canonical event -- signing as one and shipping the other must
        // still verify. This guards against a serializer that emits "1.0",
        // which would break every legitimately-signed integer-valued event.
        let id = event_id(41);
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert(
            "count".to_owned(),
            prost_types::Value { kind: Some(prost_types::value::Kind::NumberValue(1.0)) },
        );
        let signed = sign(envelope);
        send_envelope(&channel, signed).await.expect("1.0 canonicalizes as 1 and must be accepted");
        assert_landed_exactly_once("float 1.0 == 1", &id);

        // Negative zero must canonicalize to 0 per RFC 8785.
        let id = event_id(42);
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert(
            "zero".to_owned(),
            prost_types::Value { kind: Some(prost_types::value::Kind::NumberValue(-0.0)) },
        );
        let signed = sign(envelope);
        send_envelope(&channel, signed).await.expect("-0 canonicalizes as 0 and must be accepted");
        assert_landed_exactly_once("negative zero", &id);
    });
}

#[test]
fn non_finite_numbers_and_null_bytes_are_handled_deterministically() {
    if skip("non_finite_numbers_and_null_bytes_are_handled_deterministically") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // NaN / Infinity have no JSON representation. They must be a typed
        // rejection, never a panic and never a silently-coerced value.
        for (index, (label, number)) in
            [("NaN", f64::NAN), ("+Inf", f64::INFINITY), ("-Inf", f64::NEG_INFINITY)]
                .into_iter()
                .enumerate()
        {
            let id = event_id(50 + index as u32);
            let mut envelope = base_envelope(&id);
            envelope.data.as_mut().unwrap().fields.insert(
                "n".to_owned(),
                prost_types::Value { kind: Some(prost_types::value::Kind::NumberValue(number)) },
            );
            envelope.integrity.as_mut().unwrap().event_hash = "c".repeat(64);
            let status = send_envelope(&channel, envelope)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{label}: {status:?}");
            assert_nothing_landed(label, &id);
        }

        // A NUL and an RTL override inside a *data value* are legal UTF-8 and
        // are hashed verbatim, so a correctly-signed envelope is accepted --
        // what matters is that they cannot appear in an *identifier*.
        let id = event_id(53);
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert(
            "payload".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "before\u{0}after\u{202e}reversed".to_owned(),
                )),
            },
        );
        let signed = sign(envelope);
        send_envelope(&channel, signed).await.expect("control chars in a data value hash verbatim");
        assert_landed_exactly_once("NUL and RTL override in data value", &id);
    });
}
