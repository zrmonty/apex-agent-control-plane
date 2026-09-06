//! Opt-in native TypeScript -> authenticated Rust -> recovered durable journal.
//! The fixture reader is test-only, not production enrollment-file provenance.
use super::{
    tests::{document, enrollment},
    tls_tests::{leaf, pki},
    *,
};
use crate::{
    AuthenticatedGrpcService, AuthenticatedIngestAdapter, BearerTokenVerifier, EventOutbox,
    FileIdempotencyStore, FileOutbox, InMemoryPublisher, IngestGateway, OutboxedPublisher,
    bounded_event_ingest_server, proto,
};
use prost::Message;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[test]
fn managed_evidence_typescript_client_durable_microseconds() {
    let Ok(node) = std::env::var("APEX_MCP_EVIDENCE_NODE") else {
        eprintln!("SKIP cross-language: APEX_MCP_EVIDENCE_NODE absent");
        return;
    };
    let root = PathBuf::from(std::env::var("APEX_BROWSER_TEST_PKI_DIR").expect("explicit PKI"));
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let package = workspace.join("apps/mcp-gateway");
    crate::install_rustls_provider();
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let base = workspace
        .join(".superpowers/sdd/2026-09-05-runtime-execution-continuation")
        .join(format!("typed-evidence-{nonce}"));
    fs::create_dir(&base).unwrap();
    let profile = enrollment(
        "managed-evidence",
        "000000000001",
        &format!("{:x}", Sha256::digest(b"public-test-evidence-token")),
        &leaf(&root, "agent-workload-client.pem"),
    )
    .replace(
        "\"namespace_id\":\"managed-evidence\"",
        "\"namespace_id\":\"ns\"",
    );
    let bytes = document(&profile);
    let (owner, resolver) = ManagedEvidenceOwner::start_reader(move || Ok(bytes.clone())).unwrap();
    let outbox_path = base.join("outbox.jsonl");
    let gateway = IngestGateway::with_idempotency_store(
        OutboxedPublisher::new(
            InMemoryPublisher::default(),
            FileOutbox::open(&outbox_path, &base, 64).unwrap(),
        ),
        Box::new(FileIdempotencyStore::open(&base.join("idempotency.jsonl"), &base, 64).unwrap()),
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
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let output = runtime.block_on(async {
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
        let mut command = Command::new(node);
        command.current_dir(&package);
        if let Some(probe) = std::env::var_os("APEX_MCP_EVIDENCE_PROBE") {
            command.arg(probe); // Explicit opt-in compiled Linux test probe only.
        } else {
            command
                .arg(package.join("node_modules/tsx/dist/cli.mjs"))
                .arg(package.join("scripts/managed-evidence-probe.ts"));
        }
        let mut child = command
            .arg(port.to_string())
            .arg(&root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let output = child.wait_with_output().unwrap();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        output
    });
    drop(owner);
    assert!(
        output.status.success(),
        "typed probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let rows: Vec<_> = stdout
        .lines()
        .map(|line| line.split('|').collect::<Vec<_>>())
        .collect();
    assert_eq!(rows.len(), 3);
    let mut recovered = FileOutbox::open(&outbox_path, &base, 64).unwrap();
    let events = recovered.pending_batch(64).unwrap();
    assert_eq!(
        events.len(),
        3,
        "duplicate admissions do not create more durable events"
    );
    for row in rows {
        assert_eq!(row.len(), 3);
        let event = events
            .iter()
            .find(|event| event.event_id() == row[1])
            .unwrap();
        let envelope = proto::EventEnvelope::decode(event.envelope()).unwrap();
        assert_eq!(envelope.integrity.as_ref().unwrap().event_hash, row[2]);
        assert_eq!(crate::canonical_event_hash(&envelope).unwrap(), row[2]);
        let data = envelope.data.as_ref().unwrap();
        let string = |key: &str| match data.fields[key].kind.as_ref().unwrap() {
            prost_types::value::Kind::StringValue(value) => value.clone(),
            _ => panic!("expected exact decimal string"),
        };
        let us: u64 = row[0].parse().unwrap();
        assert_eq!(string("duration_us"), row[0]);
        assert_eq!(string("duration_ns"), (us * 1000).to_string());
        assert_eq!(
            string("observed_at_unix_us"),
            (9_007_199_254_740_993u64 + us).to_string()
        );
        assert_eq!(event.workspace_id(), "work");
        assert_eq!(event.namespace_id(), "ns");
    }
    eprintln!(
        "native TS -> Rust mTLS -> recovered fsync journal: 1/7/999us; {}",
        base.display()
    );
}
