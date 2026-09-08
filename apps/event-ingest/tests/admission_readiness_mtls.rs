#![cfg(feature = "test-support")]
//! Synthetic PKI, real TLS/HTTP2 RPC and actual file-backed admission owners.
//! This is not managed enrollment, Postgres, guard isolation or release evidence.
use apex_durability::{FileIdempotencyStore, FileOutbox, OutboxedPublisher};
use apex_event_ingest::{
    AuthenticatedGrpcService, AuthenticatedIngestAdapter, Caller, CallerVerifier, EventPublisher,
    GatewayError, IngestGateway, IngestRequest, PeerIdentity, PublishOutcome, proto,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Duration};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};

const CA: &str = include_str!("readiness-pki/ca.pem");
const SERVER: &str = include_str!("readiness-pki/server.pem");
const SERVER_KEY: &str = include_str!("readiness-pki/server-key.pem");
const CLIENT: &str = include_str!("readiness-pki/client.pem");
const CLIENT_KEY: &str = include_str!("readiness-pki/client-key.pem");
const WRONG: &str = include_str!("readiness-pki/wrong-client.pem");
const WRONG_KEY: &str = include_str!("readiness-pki/wrong-client-key.pem");
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct NoFanout;
impl EventPublisher for NoFanout {
    fn publish(&mut self, _: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        panic!("readiness cannot fan out")
    }
}
struct Pinned;
impl CallerVerifier for Pinned {
    fn verify(&self, _: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        panic!("actual TLS peer required")
    }
    fn verify_with_peer(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        let cert = CertificateDer::from_pem_slice(CLIENT.as_bytes()).unwrap();
        let expected: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        if peer.map(|p| p.certificate_sha256) != Some(expected)
            || metadata.get("authorization").and_then(|v| v.to_str().ok())
                != Some("Bearer synthetic-readiness")
        {
            return Err(GatewayError::unauthenticated());
        }
        Caller::authenticated_for_agent("workload", "evidence", ["acme/prod"])
    }
}
fn request(token: &str) -> tonic::Request<proto::EvidenceAdmissionProbeRequest> {
    let mut request = tonic::Request::new(proto::EvidenceAdmissionProbeRequest {
        schema_version: 1,
        request_nonce: vec![6; 32],
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        agent_id: "evidence".into(),
    });
    request
        .metadata_mut()
        .insert("authorization", token.parse().unwrap());
    request
}

#[tokio::test]
async fn real_readiness_rpc_requires_exact_tls_token_pair_and_never_writes_an_event() {
    apex_durability::install_rustls_provider();
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let dir = Directory(std::env::temp_dir().join(format!(
        "apex-ready-rpc-{:032x}",
        u128::from_le_bytes(nonce)
    )));
    fs::create_dir(&dir.0).unwrap();
    let outbox_path = dir.0.join("outbox.jsonl");
    let id_path = dir.0.join("idempotency.jsonl");
    let outbox = FileOutbox::open(&outbox_path, &dir.0, 32).unwrap();
    let idempotency = FileIdempotencyStore::open(&id_path, &dir.0, 32).unwrap();
    let service = AuthenticatedGrpcService::new(
        AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
            OutboxedPublisher::new(NoFanout, outbox),
            Box::new(idempotency),
        )),
        Pinned,
    );
    let readiness =
        proto::evidence_admission_readiness_server::EvidenceAdmissionReadinessServer::new(
            service.admission_readiness_service(),
        )
        .max_decoding_message_size(1024);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(SERVER, SERVER_KEY))
                    .client_ca_root(Certificate::from_pem(CA)),
            )
            .unwrap()
            .add_service(readiness)
            .add_service(apex_event_ingest::bounded_event_ingest_server(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            ),
    );
    for (cert, key, token, allowed) in [
        (CLIENT, CLIENT_KEY, "Bearer synthetic-readiness", true),
        (CLIENT, CLIENT_KEY, "Bearer wrong", false),
        (WRONG, WRONG_KEY, "Bearer synthetic-readiness", false),
    ] {
        let endpoint = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .timeout(Duration::from_secs(3))
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(CA))
                    .domain_name("gateway.test")
                    .identity(Identity::from_pem(cert, key)),
            )
            .unwrap();
        let mut client =
            proto::evidence_admission_readiness_client::EvidenceAdmissionReadinessClient::new(
                endpoint.connect().await.unwrap(),
            );
        let result = client.check(request(token)).await;
        if allowed {
            let reply = result.unwrap().into_inner();
            assert!(reply.ready);
            assert_eq!(reply.request_nonce, vec![6; 32]);
        } else {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
        }
    }
    assert!(fs::read(&outbox_path).unwrap().is_empty());
    assert!(fs::read(&id_path).unwrap().is_empty());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
