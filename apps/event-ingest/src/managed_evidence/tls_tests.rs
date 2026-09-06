//! Real TLS and fsync-backed canonical admission. The enrollment IO seam is
//! explicitly test-only on Windows; this is not production ACL evidence.
use super::{
    owner::ManagedEvidenceOwner,
    tests::{document, enrollment},
    *,
};
use crate::{
    AuthenticatedGrpcService, AuthenticatedIngestAdapter, BearerTokenVerifier, EventOutbox,
    FileIdempotencyStore, FileOutbox, InMemoryPublisher, IngestGateway, IngestRequest,
    OutboxedPublisher, bounded_event_ingest_server, proto,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};

pub(super) fn pki(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join("trusted-host").join(name)).expect("existing PKI")
}
pub(super) fn leaf(root: &Path, name: &str) -> String {
    let certificate = CertificateDer::from_pem_slice(&pki(root, name)).unwrap();
    format!("{:x}", Sha256::digest(certificate.as_ref()))
}
fn event(index: u64, agent: &str, namespace: &str, actor: &str) -> proto::EventEnvelope {
    let mut envelope = proto::EventEnvelope {
        event_id: format!("01990000-0000-7000-8000-{index:012x}"),
        timestamp: "2026-09-05T00:00:00.000000Z".into(),
        r#type: 1,
        agent_id: agent.into(),
        run_id: "run-evidence".into(),
        trace_id: "trace-evidence".into(),
        scope: Some(proto::Scope {
            workspace_id: "work".into(),
            namespace_id: namespace.into(),
            agent_group_ids: vec![],
        }),
        actor: Some(proto::Actor {
            r#type: 2,
            id: actor.into(),
        }),
        version: Some(proto::Version {
            agent_code: "code".into(),
            prompt: "prompt".into(),
            model: "model".into(),
        }),
        data: Some(prost_types::Struct::default()),
        integrity: Some(proto::Integrity {
            prev_hash: None,
            event_hash: String::new(),
        }),
        schema_version: 1,
        ..Default::default()
    };
    envelope.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&envelope).unwrap();
    envelope
}
fn request(envelope: proto::EventEnvelope, token: &str) -> tonic::Request<proto::EventEnvelope> {
    let mut request = tonic::Request::new(envelope);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}
async fn client(
    root: &Path,
    address: std::net::SocketAddr,
    identity: &str,
) -> proto::event_ingest_client::EventIngestClient<Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pki(root, "ca.pem")))
        .domain_name("localhost")
        .identity(Identity::from_pem(
            pki(root, &format!("{identity}.pem")),
            pki(root, &format!("{identity}.key")),
        ));
    let endpoint = Channel::from_shared(format!("https://{address}"))
        .unwrap()
        .tls_config(tls)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match endpoint.clone().connect().await {
            Ok(channel) => return proto::event_ingest_client::EventIngestClient::new(channel),
            Err(error) if Instant::now() >= deadline => panic!("real TLS failed: {error}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

#[test]
fn managed_evidence_real_mtls_two_identities_canonical_durable_admission() {
    let Ok(root) = std::env::var("APEX_BROWSER_TEST_PKI_DIR") else {
        eprintln!("SKIP real TLS: APEX_BROWSER_TEST_PKI_DIR absent");
        return;
    };
    let root = PathBuf::from(root);
    crate::install_rustls_provider();
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.superpowers/sdd/2026-09-05-runtime-execution-continuation")
        .join(format!("evidence-tls-{nonce}"));
    fs::create_dir(&base).unwrap();
    let file = base.join("enrollment.json");
    let a = enrollment(
        "agent-a",
        "000000000001",
        &format!("{:x}", Sha256::digest(b"token-a")),
        &leaf(&root, "agent-workload-client.pem"),
    );
    let b = enrollment(
        "agent-b",
        "000000000002",
        &format!("{:x}", Sha256::digest(b"token-b")),
        &leaf(&root, "agent-workload-b-client.pem"),
    );
    fs::write(&file, document(&format!("{a},{b}"))).unwrap();
    // This function exists only in cfg(test). Production start never accepts
    // an injected reader or a Windows permission waiver.
    let read_path = file.clone();
    let (owner, resolver) = ManagedEvidenceOwner::start_reader(move || {
        fs::read(&read_path).map_err(|_| EnrollmentError)
    })
    .unwrap();
    let outbox_path = base.join("outbox.jsonl");
    let idem_path = base.join("idempotency.jsonl");
    let gateway = IngestGateway::with_idempotency_store(
        OutboxedPublisher::new(
            InMemoryPublisher::default(),
            FileOutbox::open(&outbox_path, &base, 64).unwrap(),
        ),
        Box::new(FileIdempotencyStore::open(&idem_path, &base, 64).unwrap()),
    );
    let ephemeral: Arc<std::sync::Mutex<Box<dyn crate::EphemeralStore>>> = Arc::new(
        std::sync::Mutex::new(Box::new(crate::InMemoryEphemeralStore::new())),
    );
    let service = AuthenticatedGrpcService::new(
        AuthenticatedIngestAdapter::new(gateway),
        BearerTokenVerifier::new_strict(resolver).with_ephemeral_store(ephemeral.clone()),
    )
    .with_ephemeral_store(ephemeral);
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            pki(&root, "control-plane-server.pem"),
            pki(&root, "control-plane-server.key"),
        ))
        .client_ca_root(Certificate::from_pem(pki(&root, "ca.pem")))
        .client_auth_optional(false);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let incoming = tonic::transport::server::TcpIncoming::from(
            tokio::net::TcpListener::from_std(listener).unwrap(),
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(bounded_event_ingest_server(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let mut ca = client(&root, address, "agent-workload-client").await;
        let mut cb = client(&root, address, "agent-workload-b-client").await;
        let no_certificate = Channel::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(pki(&root, "ca.pem")))
                    .domain_name("localhost"),
            )
            .unwrap();
        if let Ok(channel) = no_certificate.connect().await {
            let mut unauthenticated = proto::event_ingest_client::EventIngestClient::new(channel);
            assert!(
                unauthenticated
                    .ingest(request(
                        event(11, "agent-a", "agent-a", "agent-a"),
                        "token-a"
                    ))
                    .await
                    .is_err(),
                "server must require the actual client certificate"
            );
        }
        for (client, token, agent, index) in [
            (&mut ca, "token-a", "agent-a", 1),
            (&mut cb, "token-b", "agent-b", 2),
        ] {
            assert!(
                !client
                    .ingest(request(event(index, agent, agent, agent), token))
                    .await
                    .expect("durable admission over actual TLS")
                    .into_inner()
                    .duplicate
            );
            assert!(
                client
                    .ingest(request(event(index, agent, agent, agent), token))
                    .await
                    .unwrap()
                    .into_inner()
                    .duplicate
            );
        }
        for (envelope, token, code) in [
            (
                event(3, "agent-b", "agent-b", "agent-b"),
                "token-a",
                tonic::Code::PermissionDenied,
            ),
            (
                event(4, "agent-a", "agent-b", "agent-a"),
                "token-a",
                tonic::Code::PermissionDenied,
            ),
            (
                event(5, "agent-a", "agent-a", "agent-b"),
                "token-a",
                tonic::Code::PermissionDenied,
            ),
            (
                event(6, "agent-a", "agent-a", "agent-a"),
                "token-b",
                tonic::Code::Unauthenticated,
            ),
            (
                event(7, "agent-a", "agent-a", "agent-a"),
                "wrong-token",
                tonic::Code::Unauthenticated,
            ),
        ] {
            assert_eq!(
                ca.ingest(request(envelope, token))
                    .await
                    .unwrap_err()
                    .code(),
                code
            );
        }
        assert_eq!(
            cb.ingest(request(
                event(8, "agent-a", "agent-a", "agent-a"),
                "token-a"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
        // Removal must deny a previously successful credential on the SAME
        // TLS channel, proving the verifier has no auth-allow cache.
        fs::write(&file, document(&b)).unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            ca.ingest(request(
                event(9, "agent-a", "agent-a", "agent-a"),
                "token-a"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
        assert!(
            cb.ingest(request(
                event(2, "agent-b", "agent-b", "agent-b"),
                "token-b"
            ))
            .await
            .unwrap()
            .into_inner()
            .duplicate
        );
        // A corrupt replacement poisons all credentials, including a prior
        // successful B request. The two already accepted rows stay durable.
        fs::write(&file, b"{invalid").unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            cb.ingest(request(
                event(10, "agent-b", "agent-b", "agent-b"),
                "token-b"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
        drop(ca);
        drop(cb);
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    });
    drop(owner);
    // Reopen actual journals after the entire server has released its state.
    let mut recovered = FileOutbox::open(&outbox_path, &base, 64).unwrap();
    let events = recovered.pending_batch(64).unwrap();
    assert_eq!(
        events.len(),
        2,
        "only the two authorized events were durable"
    );
    assert!(events.iter().any(|e| e.namespace_id() == "agent-a"));
    assert!(events.iter().any(|e| e.namespace_id() == "agent-b"));
    for (index, agent) in [(1, "agent-a"), (2, "agent-b")] {
        let expected = event(index, agent, agent, agent);
        let row = events
            .iter()
            .find(|e| e.event_id() == expected.event_id)
            .unwrap();
        assert_eq!(row.envelope(), prost::Message::encode_to_vec(&expected));
    }
    eprintln!(
        "real TLS + recovered fsync outbox PASS; fixture {}",
        base.display()
    );
}
