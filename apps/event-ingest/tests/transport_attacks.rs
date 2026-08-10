//! Transport-layer attacks against a live gateway.
//!
//! `adversarial_transport.rs` proves the client-certificate *matrix* (anonymous,
//! untrusted CA, self-signed, expired, not-yet-valid, wrong SAN, wrong EKU) is
//! refused at the handshake. These are the cases that survive the handshake and
//! have to be caught above it, plus the negotiable-feature surfaces.
//!
//! ```text
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18445 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//!   cargo test --test transport_attacks --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};

use apex_event_ingest::{canonical_event_hash, proto};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const AGENT_ID: &str = "reference-agent";

fn endpoint() -> Option<String> {
    std::env::var("APEX_ADVERSARIAL_GATEWAY")
        .ok()
        .filter(|v| !v.is_empty())
}

fn skip(name: &str) -> bool {
    if endpoint().is_none() {
        eprintln!("skip {name}: set APEX_ADVERSARIAL_GATEWAY to a running gateway");
        return true;
    }
    false
}

fn secrets_dir() -> PathBuf {
    std::env::var("APEX_ADVERSARIAL_SECRETS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/compose/live-mtls/secrets-host")
        })
}

fn read(root: &Path, name: &str) -> Vec<u8> {
    std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("missing fixture {name}: {e}"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn channel_with(cert: &str, key: &str) -> Result<Channel, tonic::transport::Error> {
    let root = secrets_dir();
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&root, "ca.pem")))
        .identity(Identity::from_pem(read(&root, cert), read(&root, key)))
        .domain_name("localhost");
    Channel::from_shared(endpoint().unwrap())
        .unwrap()
        .tls_config(tls)?
        .connect()
        .await
}

fn bearer() -> String {
    String::from_utf8(read(&secrets_dir(), "ingest-bearer-token"))
        .unwrap()
        .trim()
        .to_owned()
}

fn base(event_id: &str) -> proto::EventEnvelope {
    let mut data = prost_types::Struct::default();
    data.fields.insert(
        "note".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("transport".to_owned())),
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
        (nonce << 24) | 0x00bb_0000 | u64::from(suffix)
    )
}

async fn ingest(
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

// ---------------------------------------------------------------------------
// 1. Certificate swap on a new connection
// ---------------------------------------------------------------------------

/// Identity must be re-derived per connection, never inherited.
///
/// The certificate matrix in `adversarial_transport.rs` covers certificates that
/// fail the *handshake*. This is the case that passes it: a second certificate
/// issued by the same trusted CA, with the right EKU and SAN, that is simply
/// not the pinned one. `ingest-nats-client` is exactly that -- a legitimate
/// client leaf for a different purpose.
///
/// The attack is a caller that establishes an authorized session, then opens a
/// second connection with a different certificate and relies on the gateway
/// having cached the first identity (per token, per bearer credential, or
/// process-wide). Both connections carry the *same* valid bearer token, so the
/// certificate pin is the only thing separating them.
#[test]
fn a_different_valid_certificate_on_a_new_connection_is_not_inherited() {
    if skip("a_different_valid_certificate_on_a_new_connection_is_not_inherited") {
        return;
    }
    runtime().block_on(async {
        // Connection 1: the pinned identity. Must work.
        let authorized = channel_with("ingest-http-client.pem", "ingest-http-client.key")
            .await
            .expect("the pinned client certificate must connect");
        ingest(&authorized, sign(base(&event_id(1))))
            .await
            .expect("the pinned identity must be admitted");

        // Connection 2: a different, equally CA-trusted client leaf, same
        // bearer token. Must be refused on the certificate pin alone.
        let swapped = channel_with("ingest-nats-client.pem", "ingest-nats-client.key").await;
        match swapped {
            Err(_) => { /* refused at the handshake: also acceptable */ }
            Ok(channel) => {
                let status = ingest(&channel, sign(base(&event_id(2))))
                    .await
                    .expect_err(
                        "a CA-trusted but unpinned client certificate must not be admitted, \
                         even carrying a valid bearer token",
                    );
                assert!(
                    matches!(
                        status.code(),
                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                    ),
                    "certificate swap: expected an identity rejection, got {status:?}"
                );
            }
        }

        // Connection 1 must be unaffected by the rejected attempt: a failed
        // swap must not poison or downgrade an already-authorized session.
        ingest(&authorized, sign(base(&event_id(3))))
            .await
            .expect("the original authorized connection must survive a rejected swap");

        // ...and a freshly opened connection with the pinned certificate must
        // still work, i.e. the rejection did not blocklist the identity.
        let reopened = channel_with("ingest-http-client.pem", "ingest-http-client.key")
            .await
            .expect("the pinned identity must still connect after a rejected swap");
        ingest(&reopened, sign(base(&event_id(4))))
            .await
            .expect("re-connecting with the pinned identity must still be admitted");
    });
}

// ---------------------------------------------------------------------------
// 2. Negotiable compression (decompression-bomb surface)
// ---------------------------------------------------------------------------

/// A compression bomb needs compression to be negotiable. It is not.
///
/// tonic enables per-service compression only when the generated server is
/// explicitly told to (`accept_compressed`). `bounded_event_ingest_server` does
/// not, so a client advertising `grpc-encoding: gzip` must be refused rather
/// than served -- there is no decompressor in the request path to feed an
/// expansion bomb to.
///
/// This is a surface-absence test: it fails if someone later turns compression
/// on without also bounding the decompressed size.
#[test]
fn grpc_compression_is_not_negotiable() {
    if skip("grpc_compression_is_not_negotiable") {
        return;
    }
    runtime().block_on(async {
        let channel = channel_with("ingest-http-client.pem", "ingest-http-client.key")
            .await
            .expect("authorized channel");

        for encoding in ["gzip", "deflate", "zstd", "snappy"] {
            let mut request = tonic::Request::new(sign(base(&event_id(10))));
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {}", bearer()).parse().unwrap());
            // Claim a compressed body without compressing it. If the server
            // negotiates the encoding it will try to inflate the plaintext
            // frame; if it does not, it must reject the request outright.
            request
                .metadata_mut()
                .insert("grpc-encoding", encoding.parse().unwrap());

            let result = proto::event_ingest_client::EventIngestClient::new(channel.clone())
                .ingest(request)
                .await;
            let status = result.expect_err(
                "a request claiming a compressed body must not be accepted while \
                 the server advertises no compression support",
            );
            assert!(
                matches!(
                    status.code(),
                    tonic::Code::Unimplemented | tonic::Code::InvalidArgument
                ),
                "grpc-encoding {encoding}: expected the encoding to be refused, got {status:?}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// 3. SQL metacharacters on the wire
// ---------------------------------------------------------------------------

/// Scope identifiers carrying SQL metacharacters must never reach a query.
///
/// Parameterisation was confirmed by reading the code. This confirms the outer
/// boundary empirically: `is_scope_identifier` restricts workspace and
/// namespace to `[A-Za-z0-9._:-]`, so a quote, semicolon, or comment marker is
/// refused at admission and never becomes a bound parameter in the first place.
/// Defence in depth, asserted from the outside, where an attacker actually is.
#[test]
fn sql_metacharacters_in_scope_identifiers_are_refused_at_admission() {
    if skip("sql_metacharacters_in_scope_identifiers_are_refused_at_admission") {
        return;
    }
    let payloads = [
        "acme'; DROP TABLE apex_event_outbox; --",
        "acme' OR '1'='1",
        "acme\"; DELETE FROM apex_ingest_idempotency WHERE ''='",
        "acme/**/UNION/**/SELECT",
        "acme\\'; TRUNCATE apex_event_outbox; --",
        "acme%27%20OR%201=1",
        "acme\0'; DROP TABLE apex_event_outbox; --",
    ];
    runtime().block_on(async {
        let channel = channel_with("ingest-http-client.pem", "ingest-http-client.key")
            .await
            .expect("authorized channel");

        for (index, payload) in payloads.iter().enumerate() {
            // Workspace position.
            let mut envelope = base(&event_id(20 + index as u32));
            envelope.scope.as_mut().unwrap().workspace_id = (*payload).to_owned();
            let status = ingest(&channel, sign(envelope))
                .await
                .expect_err("a SQL-metacharacter workspace_id must be refused");
            assert!(
                matches!(
                    status.code(),
                    tonic::Code::PermissionDenied
                        | tonic::Code::InvalidArgument
                        | tonic::Code::Unauthenticated
                ),
                "workspace payload {payload:?}: unexpected {status:?}"
            );

            // Namespace position.
            let mut envelope = base(&event_id(40 + index as u32));
            envelope.scope.as_mut().unwrap().namespace_id = (*payload).to_owned();
            let status = ingest(&channel, sign(envelope))
                .await
                .expect_err("a SQL-metacharacter namespace_id must be refused");
            assert!(
                matches!(
                    status.code(),
                    tonic::Code::PermissionDenied
                        | tonic::Code::InvalidArgument
                        | tonic::Code::Unauthenticated
                ),
                "namespace payload {payload:?}: unexpected {status:?}"
            );

            // event_id position: must be a lowercase UUIDv7, so anything else
            // is refused before it can be parsed into a Uuid bind parameter.
            let mut envelope = base("018f5c91-2d88-7c00-8000-000000000001");
            envelope.event_id = format!("018f5c91-2d88-7c00-8000-{payload}");
            let status = ingest(&channel, sign(envelope))
                .await
                .expect_err("a SQL-metacharacter event_id must be refused");
            assert!(
                matches!(
                    status.code(),
                    tonic::Code::InvalidArgument | tonic::Code::PermissionDenied
                ),
                "event_id payload {payload:?}: unexpected {status:?}"
            );
        }

        // The gateway must still be healthy afterwards -- nothing above may
        // have taken a table, a connection, or the process with it.
        ingest(&channel, sign(base(&event_id(60))))
            .await
            .expect("the gateway must still admit a valid event after the injection corpus");
    });
}

// ---------------------------------------------------------------------------
// 4. TLS renegotiation
// ---------------------------------------------------------------------------

/// Renegotiation is structurally unavailable, and this pins the reason.
///
/// The gateway terminates TLS with rustls, which implements neither TLS 1.2
/// renegotiation nor TLS 1.3 post-handshake client authentication as a server.
/// There is no code path to disable and no configuration that re-enables it, so
/// the renegotiation-based attacks (identity change mid-connection, the
/// CVE-2009-3555 prefix injection class, renegotiation-flood DoS) have no
/// surface here.
///
/// Rather than assert on a negative that no client library will even emit, this
/// pins the property renegotiation would be used to subvert: the connection's
/// identity is fixed for its lifetime, and a long-lived connection keeps
/// getting the same answer. `crate::Cargo.toml` pins rustls with only `tls12`
/// and `ring`; if someone swaps in an OpenSSL-backed terminator, the
/// certificate-swap test above is the one that starts mattering.
#[test]
fn a_long_lived_connection_keeps_one_fixed_identity() {
    if skip("a_long_lived_connection_keeps_one_fixed_identity") {
        return;
    }
    runtime().block_on(async {
        let channel = channel_with("ingest-http-client.pem", "ingest-http-client.key")
            .await
            .expect("authorized channel");
        // Many requests over one connection: each must be authorized on its
        // own, and the answer must not drift.
        for index in 0..12 {
            ingest(&channel, sign(base(&event_id(70 + index))))
                .await
                .unwrap_or_else(|status| {
                    panic!("request {index} on a long-lived connection failed: {status:?}")
                });
        }

        // An unauthenticated request on that same established connection must
        // still be refused: authorization is per request, not per handshake.
        let anonymous = tonic::Request::new(sign(base(&event_id(90))));
        let status = proto::event_ingest_client::EventIngestClient::new(channel.clone())
            .ingest(anonymous)
            .await
            .expect_err(
                "a request without a bearer credential must be refused even on a \
                 connection whose handshake already presented a pinned certificate",
            );
        assert_eq!(
            status.code(),
            tonic::Code::Unauthenticated,
            "unauthenticated request on an authorized connection: {status:?}"
        );
    });
}
