//! Adversarial data-admission corpus against a **live** ingest gateway:
//! oversized/deeply-nested payloads and protobuf-level malformation (truncated
//! frames, wrong wire types, non-UTF8 strings, out-of-range enums, missing
//! required sub-messages, malformed ids and timestamps).
//!
//! Every other test in this crate exercises the gateway in-process. This one
//! speaks real gRPC over a real mTLS connection to a running
//! `apex-event-ingest`, sends malformed / oversized envelopes -- including raw
//! bytes the generated `EventEnvelope` type cannot even represent -- and then
//! **queries the downstream stores directly** to prove nothing landed.
//!
//! A typed rejection from the gateway is not, on its own, evidence. A rejected
//! request that still leaves a ClickHouse row, an archive object, a pending
//! outbox entry, or a poisoned idempotency key is a finding. Each case
//! therefore asserts the negative against every store.
//!
//! Enabled only when `APEX_ADVERSARIAL_GATEWAY` is set; skipped otherwise so
//! offline unit CI stays green. See the sibling `adversarial_*.rs` files for
//! the rest of this corpus: integrity/canonicalization, scope/replay, and
//! transport admission.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test adversarial_malformed_payloads --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::process::Command;

use apex_event_ingest::{canonical_event_hash, proto};
use prost::Message;
use prost::bytes::{Buf, BufMut};
use prost::encoding::{DecodeContext, WireType};
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

// ---------------------------------------------------------------------------
// Raw-bytes message: lets the corpus put arbitrary protobuf on the wire
// ---------------------------------------------------------------------------

/// Passthrough `prost::Message` so a test can transmit bytes that the generated
/// `EventEnvelope` type cannot represent (wrong wire types, truncated frames,
/// unknown field numbers, non-UTF8 string fields).
#[derive(Clone, Debug, Default)]
struct RawMessage(Vec<u8>);

impl Message for RawMessage {
    fn encode_raw(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        prost::encoding::skip_field(wire_type, tag, buf, ctx)
    }

    fn encoded_len(&self) -> usize {
        self.0.len()
    }

    fn clear(&mut self) {
        self.0.clear();
    }
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

async fn send_raw(channel: &Channel, bytes: Vec<u8>) -> Result<proto::IngestResponse, tonic::Status> {
    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready().await.map_err(|error| tonic::Status::unavailable(error.to_string()))?;
    let codec: tonic_prost::ProstCodec<RawMessage, proto::IngestResponse> = Default::default();
    let path = tonic::codegen::http::uri::PathAndQuery::from_static("/apex.v1.EventIngest/Ingest");
    grpc.unary(authorized_request(RawMessage(bytes)), path, codec)
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
// 5. Size, shape, and protobuf-level malformation
// ---------------------------------------------------------------------------

#[test]
fn oversized_and_deeply_nested_payloads_are_rejected() {
    if skip("oversized_and_deeply_nested_payloads_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // Oversized: beyond MAX_ENVELOPE_BYTES.
        let id = event_id(100);
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert(
            "blob".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("A".repeat(300 * 1024))),
            },
        );
        envelope.integrity.as_mut().unwrap().event_hash = "d".repeat(64);
        let status = send_envelope(&channel, envelope).await.expect_err("oversized must be rejected");
        assert!(
            matches!(
                status.code(),
                tonic::Code::InvalidArgument | tonic::Code::ResourceExhausted | tonic::Code::OutOfRange
            ),
            "oversized: unexpected {status:?}"
        );
        assert_nothing_landed("oversized envelope", &id);

        // Recursion depth: nest Struct values past the accepted limit.
        let id = event_id(101);
        let mut deepest = prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("bottom".to_owned())),
        };
        for _ in 0..200 {
            let mut level = prost_types::Struct::default();
            level.fields.insert("n".to_owned(), deepest);
            deepest = prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(level)),
            };
        }
        let mut envelope = base_envelope(&id);
        envelope.data.as_mut().unwrap().fields.insert("deep".to_owned(), deepest);
        envelope.integrity.as_mut().unwrap().event_hash = "e".repeat(64);
        let status = send_envelope(&channel, envelope).await.expect_err("deep nesting must be rejected");
        // prost's decoder hits its own recursion limit before the envelope ever
        // reaches the gateway's MAX_STRUCT_DEPTH check, so this rejection is
        // produced entirely inside the codec. It must still land in the
        // gateway's error contract: `InvalidArgument`, not the `Internal` that
        // tonic_prost::ProstCodec produces by default. `Internal` reads as a
        // server fault and is widely retried, so a client with a deterministic
        // bad payload would resend it forever. See src/codec.rs.
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "deep nesting must be caller error, not a retryable server fault: {status:?}"
        );
        for leak in ["EventEnvelope", "Struct.fields", "struct_value", "recursion limit"] {
            assert!(
                !status.message().contains(leak),
                "deep nesting leaked decoder internals ({leak}): {}",
                status.message()
            );
        }
        assert_nothing_landed("200-level nested Struct", &id);
    });
}

#[test]
fn malformed_protobuf_frames_are_rejected() {
    if skip("malformed_protobuf_frames_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;
        let valid = valid_envelope(&event_id(110)).encode_to_vec();

        // Truncated message.
        let status = send_raw(&channel, valid[..valid.len() / 2].to_vec())
            .await
            .expect_err("truncated protobuf must be rejected");
        assert!(
            matches!(status.code(), tonic::Code::InvalidArgument | tonic::Code::Internal),
            "truncated: unexpected {status:?}"
        );

        // Wrong wire type for field 1 (event_id is a length-delimited string;
        // send it as a varint instead).
        let status = send_raw(&channel, vec![0x08, 0x2a])
            .await
            .expect_err("wrong wire type must be rejected");
        assert!(
            matches!(status.code(), tonic::Code::InvalidArgument | tonic::Code::Internal),
            "wrong wire type: unexpected {status:?}"
        );

        // Non-UTF8 bytes in a string field: field 1, length 2, invalid sequence.
        let status = send_raw(&channel, vec![0x0a, 0x02, 0xff, 0xfe])
            .await
            .expect_err("non-UTF8 string must be rejected");
        assert!(
            matches!(status.code(), tonic::Code::InvalidArgument | tonic::Code::Internal),
            "non-UTF8: unexpected {status:?}"
        );

        // Empty message: no identifiers at all.
        let status = send_raw(&channel, Vec::new()).await.expect_err("empty message must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "empty: {status:?}");

        // Unknown high field numbers are ignored by proto3 and must not change
        // the admission decision -- a valid envelope plus trailing unknown
        // fields is still valid, and its re-encoded form is what gets stored.
        let id = event_id(111);
        let mut bytes = valid_envelope(&id).encode_to_vec();
        // field 9999, varint wire type, value 1
        prost::encoding::encode_key(9999, WireType::Varint, &mut bytes);
        prost::encoding::encode_varint(1, &mut bytes);
        send_raw(&channel, bytes).await.expect("unknown fields must not break a valid envelope");
        assert_landed_exactly_once("valid envelope with unknown trailing field", &id);
    });
}

#[test]
fn out_of_range_enums_and_missing_required_fields_are_rejected() {
    if skip("out_of_range_enums_and_missing_required_fields_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        // EventType 0 (UNSPECIFIED), 13 (past the last defined value), and a
        // large sentinel must all be refused.
        for (index, bad_type) in [0_i32, 13, 9999, -1].into_iter().enumerate() {
            let id = event_id(120 + index as u32);
            let mut envelope = base_envelope(&id);
            envelope.r#type = bad_type;
            envelope.integrity.as_mut().unwrap().event_hash = "f".repeat(64);
            let status = send_envelope(&channel, envelope)
                .await
                .expect_err(&format!("EventType {bad_type} must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "type {bad_type}: {status:?}");
            assert_nothing_landed(&format!("EventType {bad_type}"), &id);
        }

        // Missing sub-messages.
        for (index, (label, mutate)) in [
            ("no scope", (|e: &mut proto::EventEnvelope| e.scope = None) as fn(&mut proto::EventEnvelope)),
            ("no actor", |e: &mut proto::EventEnvelope| e.actor = None),
            ("no version", |e: &mut proto::EventEnvelope| e.version = None),
            ("no data", |e: &mut proto::EventEnvelope| e.data = None),
            ("no integrity", |e: &mut proto::EventEnvelope| e.integrity = None),
        ]
        .into_iter()
        .enumerate()
        {
            let id = event_id(130 + index as u32);
            let mut envelope = valid_envelope(&id);
            mutate(&mut envelope);
            let status = send_envelope(&channel, envelope)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{label}: {status:?}");
            assert_nothing_landed(label, &id);
        }

        // Bad schema_version.
        let id = event_id(140);
        let mut envelope = base_envelope(&id);
        envelope.schema_version = 2;
        let signed = sign(envelope);
        let status = send_envelope(&channel, signed).await.expect_err("schema_version 2 must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "schema_version: {status:?}");
        assert_nothing_landed("schema_version 2", &id);
    });
}

#[test]
fn malformed_event_ids_and_timestamps_are_rejected() {
    if skip("malformed_event_ids_and_timestamps_are_rejected") {
        return;
    }
    runtime().block_on(async {
        let channel = authorized_channel().await;

        for (index, (label, bad_id)) in [
            ("uppercase uuid", "018F5C91-2D88-7C00-8000-0000000000FF".to_owned()),
            ("uuid v4 not v7", "018f5c91-2d88-4c00-8000-0000000000ff".to_owned()),
            ("bad variant nibble", "018f5c91-2d88-7c00-1000-0000000000ff".to_owned()),
            ("too short", "018f5c91-2d88-7c00-8000-0000000000f".to_owned()),
            ("empty", String::new()),
            ("unicode digits", "٠١٨f5c91-2d88-7c00-8000-0000000000ff".to_owned()),
        ]
        .into_iter()
        .enumerate()
        {
            let mut envelope = base_envelope(&event_id(150 + index as u32));
            envelope.event_id = bad_id;
            let signed = sign(envelope);
            let status = send_envelope(&channel, signed)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{label}: {status:?}");
        }

        for (index, (label, bad_timestamp)) in [
            ("no fractional seconds", "2026-08-06T12:00:00Z".to_owned()),
            ("offset instead of Z", "2026-08-06T12:00:00.000000+00:00".to_owned()),
            ("month 13", "2026-13-06T12:00:00.000000Z".to_owned()),
            ("day 32", "2026-08-32T12:00:00.000000Z".to_owned()),
            ("hour 24", "2026-08-06T24:00:00.000000Z".to_owned()),
            ("feb 30", "2026-02-30T12:00:00.000000Z".to_owned()),
            ("year zero", "0000-08-06T12:00:00.000000Z".to_owned()),
            ("empty", String::new()),
        ]
        .into_iter()
        .enumerate()
        {
            let id = event_id(160 + index as u32);
            let mut envelope = base_envelope(&id);
            envelope.timestamp = bad_timestamp;
            let signed = sign(envelope);
            let status = send_envelope(&channel, signed)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{label}: {status:?}");
            assert_nothing_landed(label, &id);
        }
    });
}
