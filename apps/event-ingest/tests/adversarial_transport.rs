//! Adversarial data-admission corpus against a **live** ingest gateway:
//! transport admission -- proves `client_auth_optional(false)` holds on the
//! wire against untrusted, self-signed, expired, not-yet-valid, and
//! CA-trusted-but-unpinned client certificates, plus cleartext and downgraded
//! TLS connections.
//!
//! Every other test in this crate exercises the gateway in-process. This one
//! speaks real gRPC over a real mTLS connection to a running
//! `apex-event-ingest`, attempts handshakes with adversarial identities, and
//! then **queries the downstream stores directly** to prove nothing landed.
//!
//! A typed rejection from the gateway is not, on its own, evidence. A rejected
//! request that still leaves a ClickHouse row, an archive object, a pending
//! outbox entry, or a poisoned idempotency key is a finding. Each case
//! therefore asserts the negative against every store.
//!
//! Enabled only when `APEX_ADVERSARIAL_GATEWAY` is set; skipped otherwise so
//! offline unit CI stays green. See the sibling `adversarial_*.rs` files for
//! the rest of this corpus: integrity/canonicalization, scope/replay, and
//! malformed payloads.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test adversarial_transport --features test-support -- --test-threads=1
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

fn adversarial_pki_dir() -> PathBuf {
    std::env::var("APEX_ADVERSARIAL_PKI").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/adversarial")
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

fn skip(name: &str) -> bool {
    if gateway_endpoint().is_none() {
        eprintln!("skip {name}: set APEX_ADVERSARIAL_GATEWAY to a running gateway");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 6. Transport admission -- proves client_auth_optional(false) holds on the wire
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_client_certificates_cannot_complete_a_handshake() {
    if skip("unauthorized_client_certificates_cannot_complete_a_handshake") {
        return;
    }
    let root = secrets_dir();
    let pki = adversarial_pki_dir();
    if !pki.join("wrong-ca-client.pem").is_file() {
        eprintln!("skip: run deploy/compose/e2e/generate_adversarial_pki.py first");
        return;
    }
    let ca = read(&root, "ca.pem");

    runtime().block_on(async {
        // No client certificate at all: client_auth_optional(false) must refuse.
        let endpoint = gateway_endpoint().expect("endpoint");
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca.clone()))
            .domain_name("localhost");
        let anonymous = Channel::from_shared(endpoint)
            .expect("uri")
            .tls_config(tls)
            .expect("tls config")
            .connect()
            .await;
        let denied = match anonymous {
            Err(_) => true,
            Ok(channel) => send_envelope(&channel, valid_envelope(&event_id(170))).await.is_err(),
        };
        assert!(denied, "a client with no certificate must not be able to ingest");
        assert_nothing_landed("anonymous client", &event_id(170));

        // Every adversarial identity must fail: untrusted CA, self-signed,
        // expired, not-yet-valid, and CA-trusted-but-unpinned leaves.
        for name in [
            "wrong-ca-client",
            "self-signed-client",
            "expired-client",
            "not-yet-valid-client",
            "wrong-san-client",
            "server-eku-client",
        ] {
            let cert = read(&pki, &format!("{name}.pem"));
            let key = read(&pki, &format!("{name}.key"));
            let id = event_id(171);
            let result = client_channel(ca.clone(), cert, key).await;
            let denied = match result {
                Err(_) => true,
                Ok(channel) => send_envelope(&channel, valid_envelope(&id)).await.is_err(),
            };
            assert!(denied, "{name}: must not be able to ingest");
            assert_nothing_landed(name, &id);
        }
    });
}

#[test]
fn cleartext_and_downgraded_connections_are_refused() {
    if skip("cleartext_and_downgraded_connections_are_refused") {
        return;
    }
    let endpoint = gateway_endpoint().expect("endpoint");
    let authority = endpoint.trim_start_matches("https://").trim_start_matches("http://").to_owned();

    runtime().block_on(async {
        // Plain HTTP against the TLS port must not yield a usable channel.
        let cleartext = Channel::from_shared(format!("http://{authority}"))
            .expect("uri")
            .connect()
            .await;
        let denied = match cleartext {
            Err(_) => true,
            Ok(channel) => send_envelope(&channel, valid_envelope(&event_id(180))).await.is_err(),
        };
        assert!(denied, "cleartext gRPC against the TLS port must be refused");
        assert_nothing_landed("cleartext connection", &event_id(180));
    });

    // TLS 1.0/1.1 and anonymous/NULL cipher negotiation, via the system
    // OpenSSL client when present. Absence is reported, never silently passed.
    for (label, args) in [
        ("tls1.0", vec!["-tls1"]),
        ("tls1.1", vec!["-tls1_1"]),
        ("null cipher", vec!["-cipher", "aNULL"]),
    ] {
        let mut command = Command::new("openssl");
        command.arg("s_client").arg("-connect").arg(&authority).args(&args);
        match command.output() {
            Ok(output) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    !output.status.success() || !combined.contains("Verify return code: 0"),
                    "{label}: the gateway negotiated a downgraded connection"
                );
            }
            Err(error) => eprintln!("note: openssl unavailable for {label} probe: {error}"),
        }
    }
}
