//! Adversarial data-admission corpus against a **live** ingest gateway:
//! scope/actor-identity violations and idempotent-replay handling.
//!
//! Every other test in this crate exercises the gateway in-process. This one
//! speaks real gRPC over a real mTLS connection to a running
//! `apex-event-ingest`, sends scope-violating / replayed envelopes, and then
//! **queries the downstream stores directly** to prove nothing landed (or, for
//! replay, landed exactly once).
//!
//! A typed rejection from the gateway is not, on its own, evidence. A rejected
//! request that still leaves a ClickHouse row, an archive object, a pending
//! outbox entry, or a poisoned idempotency key is a finding. Each case
//! therefore asserts the negative against every store.
//!
//! Enabled only when `APEX_ADVERSARIAL_GATEWAY` is set; skipped otherwise so
//! offline unit CI stays green. See the sibling `adversarial_*.rs` files for
//! the rest of this corpus: integrity/canonicalization, malformed payloads,
//! and transport admission.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test adversarial_scope_and_replay --features test-support -- --test-threads=1
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
fn assert_landed_exactly_once(label: &str, event_id: &str) {
    assert_eq!(clickhouse_rows(event_id), 1, "{label}: expected exactly one ClickHouse row");
    assert_eq!(archive_objects(event_id), 1, "{label}: expected exactly one archive object");
}

/// Phase 0.6: admission durably enqueues and acknowledges independently of
/// downstream fanout, which now happens in a background worker off the
/// admission call stack. An accepted response is therefore no longer proof
/// that JetStream/ClickHouse/archive already have the event -- callers that
/// need to assert on sink state must poll for the worker to catch up first.
fn wait_for_landed_exactly_once(event_id: &str, seconds: u64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if clickhouse_rows(event_id) == 1 && archive_objects(event_id) == 1 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn skip(name: &str) -> bool {
    if gateway_endpoint().is_none() {
        eprintln!("skip {name}: set APEX_ADVERSARIAL_GATEWAY to a running gateway");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 3. Scope violations and delimiter confusion
// ---------------------------------------------------------------------------

#[test]
fn scope_violations_and_delimiter_confusion_are_rejected() {
    if skip("scope_violations_and_delimiter_confusion_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // Scope the credential does not hold.
        let id = event_id(60);
        let mut envelope = base_envelope(&id);
        let scope = envelope.scope.as_mut().unwrap();
        scope.workspace_id = "other-tenant".to_owned();
        let signed = sign(envelope);
        let status = send_envelope(&channel, signed).await.expect_err("foreign workspace must be denied");
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "foreign workspace: {status:?}");
        assert_nothing_landed("foreign workspace", &id);

        // Delimiter confusion: the scope key is `workspace/namespace`. An id
        // containing the separator must not let one tenant address another.
        let id = event_id(61);
        let mut envelope = base_envelope(&id);
        let scope = envelope.scope.as_mut().unwrap();
        scope.workspace_id = "acme/prod".to_owned();
        scope.namespace_id = "x".to_owned();
        let signed = sign(envelope);
        let status = send_envelope(&channel, signed)
            .await
            .expect_err("separator inside workspace_id must be denied");
        // Stronger than a scope denial: `/` is not a legal scope-identifier
        // byte at all, so the envelope is refused structurally and the
        // `workspace/namespace` key can never be ambiguous in the first place.
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "delimiter confusion: {status:?}");
        assert!(
            status.message().contains("INVALID_ENVELOPE_STRUCTURE"),
            "delimiter confusion must be a structural rejection: {status:?}"
        );
        assert_nothing_landed("scope delimiter confusion", &id);

        // Empty and oversized identifiers.
        for (index, (label, workspace)) in [
            ("empty workspace", String::new()),
            ("oversized workspace", "a".repeat(257)),
            ("unicode workspace", "acmé".to_owned()),
            ("path traversal workspace", "acme/../other".to_owned()),
        ]
        .into_iter()
        .enumerate()
        {
            let id = event_id(62 + index as u32);
            let mut envelope = base_envelope(&id);
            envelope.scope.as_mut().unwrap().workspace_id = workspace;
            let signed = sign(envelope);
            let status = send_envelope(&channel, signed)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert!(
                matches!(status.code(), tonic::Code::PermissionDenied | tonic::Code::InvalidArgument),
                "{label}: unexpected {status:?}"
            );
            assert_nothing_landed(label, &id);
        }
    });
}

#[test]
fn actor_identity_cannot_be_minted_by_a_bound_credential() {
    if skip("actor_identity_cannot_be_minted_by_a_bound_credential") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // The credential is bound to one agent id. Claiming another agent, or a
        // non-agent actor type, must be denied.
        let id = event_id(70);
        let mut envelope = base_envelope(&id);
        envelope.agent_id = "someone-elses-agent".to_owned();
        envelope.actor = Some(proto::Actor { r#type: 2, id: "someone-elses-agent".to_owned() });
        let signed = sign(envelope);
        let status = send_envelope(&channel, signed).await.expect_err("foreign agent must be denied");
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "foreign agent: {status:?}");
        assert_nothing_landed("foreign agent_id", &id);

        // Correct agent_id but a USER actor -- a shared credential must not be
        // able to attribute events to a human identity.
        let id = event_id(71);
        let mut envelope = base_envelope(&id);
        envelope.actor = Some(proto::Actor { r#type: 1, id: AGENT_ID.to_owned() });
        let signed = sign(envelope);
        let status = send_envelope(&channel, signed).await.expect_err("USER actor must be denied");
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "user actor: {status:?}");
        assert_nothing_landed("USER actor from agent credential", &id);
    });
}

// ---------------------------------------------------------------------------
// 4. Replay and duplication
// ---------------------------------------------------------------------------

#[test]
fn replay_is_idempotent_and_tampered_replay_is_rejected() {
    if skip("replay_is_idempotent_and_tampered_replay_is_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // Exact replay: accepted as a duplicate, must not double-write.
        let id = event_id(80);
        let envelope = valid_envelope(&id);
        send_envelope(&channel, envelope.clone()).await.expect("first submission");
        let second = send_envelope(&channel, envelope.clone()).await.expect("exact replay accepted");
        assert!(second.duplicate, "exact replay must report duplicate");
        wait_for_landed_exactly_once(&id, 30);
        assert_landed_exactly_once("exact replay", &id);

        // Replay with one field changed under the same event_id: an idempotency
        // conflict, and the original row must be untouched.
        let mut tampered = base_envelope(&id);
        tampered.run_id = "run-2".to_owned();
        let tampered = sign(tampered);
        let status = send_envelope(&channel, tampered)
            .await
            .expect_err("same event_id with different content must conflict");
        // errors/gateway.rs deliberately maps IdempotencyConflict to
        // INVALID_ARGUMENT: reusing an accepted event_id for different content
        // is a caller bug, not a race the caller should retry.
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "tampered replay: {status:?}");
        assert!(
            status.message().contains("IDEMPOTENCY_CONFLICT"),
            "tampered replay must be typed as an idempotency conflict: {status:?}"
        );
        assert_landed_exactly_once("tampered replay leaves original intact", &id);
    });
}

#[test]
fn concurrent_identical_submissions_land_exactly_once() {
    if skip("concurrent_identical_submissions_land_exactly_once") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;
        let id = event_id(90);
        let envelope = valid_envelope(&id);

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let channel = channel.clone();
            let envelope = envelope.clone();
            tasks.push(tokio::spawn(async move { send_envelope(&channel, envelope).await }));
        }
        let mut accepted = 0;
        for task in tasks {
            if task.await.expect("join").is_ok() {
                accepted += 1;
            }
        }
        assert!(accepted >= 1, "at least one concurrent submission must succeed");
        // Regardless of how many callers got an OK, the stores must hold one.
        // Fanout is a background worker now, so give it time to catch up
        // before asserting on sink state.
        wait_for_landed_exactly_once(&id, 30);
        assert_landed_exactly_once("8 concurrent identical submissions", &id);
    });
}
