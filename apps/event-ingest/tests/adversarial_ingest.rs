//! Adversarial data-admission corpus against a **live** ingest gateway.
//!
//! Every other test in this crate exercises the gateway in-process. This one
//! speaks real gRPC over a real mTLS connection to a running
//! `apex-event-ingest`, sends malformed / forged / replayed / oversized /
//! scope-violating envelopes, and then **queries the downstream stores
//! directly** to prove nothing landed.
//!
//! A typed rejection from the gateway is not, on its own, evidence. A rejected
//! request that still leaves a ClickHouse row, an archive object, a pending
//! outbox entry, or a poisoned idempotency key is a finding. Each case
//! therefore asserts the negative against every store.
//!
//! Enabled only when `APEX_ADVERSARIAL_GATEWAY` is set; skipped otherwise so
//! offline unit CI stays green.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_ADVERSARIAL_OUTBOX_DIR=<gateway data dir> \
//!   cargo test --test adversarial_ingest --features test-support -- --test-threads=1
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
fn assert_landed_exactly_once(label: &str, event_id: &str) {
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
        assert_landed_exactly_once("8 concurrent identical submissions", &id);
    });
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
        // Fail-closed either way, but note WHERE it fails: prost's decoder hits
        // its own recursion limit before the envelope ever reaches the
        // gateway's MAX_STRUCT_DEPTH check, so tonic reports `Internal` with a
        // verbose decoder message instead of routing through the gateway's
        // redacted `InvalidArgument` table. Accepted here because nothing
        // lands; tracked as a diagnostics finding, since `Internal` reads as a
        // server fault and is commonly retried by clients.
        assert!(
            matches!(status.code(), tonic::Code::InvalidArgument | tonic::Code::Internal),
            "deep nesting: unexpected {status:?}"
        );
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
