//! Real loopback mTLS transport, synthetic inspected reply; no Docker or database.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, ClientTlsConfig, Server, ServerTlsConfig, server::TcpIncoming},
};

#[derive(Clone)]
struct Agent {
    pin: [u8; 32],
    calls: Arc<AtomicUsize>,
    mode: usize,
    current: Arc<AtomicBool>,
}
#[tonic::async_trait]
impl proto::runtime_network_inspection_server::RuntimeNetworkInspection for Agent {
    async fn check(
        &self,
        request: Request<proto::RuntimeNetworkInspectionRequest>,
    ) -> Result<Response<proto::RuntimeNetworkInspectionResponse>, Status> {
        let peer = apex_auth::PeerIdentity::from_request(&request)
            .ok_or_else(|| Status::unauthenticated("test peer missing"))?;
        if peer.certificate_sha256 != self.pin {
            return Err(Status::permission_denied("test peer wrong"));
        }
        assert!(request.metadata().get("authorization").is_none());
        assert!(
            request
                .metadata()
                .get_bin("apex-instance-proof-bin")
                .is_none()
        );
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let mut reply = response(request.get_ref());
        match self.mode {
            1 => {
                reply.nonce[0] ^= 1;
            }
            2 => tokio::time::sleep(Duration::from_secs(3)).await,
            3 => {
                self.current.store(false, Ordering::SeqCst);
            }
            4 if call == 0 => return Err(Status::resource_exhausted("RUNTIME_PROXY_BUSY")),
            5 => {
                self.current.store(false, Ordering::SeqCst);
                return Err(Status::resource_exhausted("RUNTIME_NETWORK_BUSY"));
            }
            6 => return Err(Status::resource_exhausted("UNKNOWN_CANARY")),
            7 => return Err(Status::permission_denied("RUNTIME_PROXY_BUSY")),
            8 => return Err(Status::unavailable("RUNTIME_PROXY_BUSY")),
            9 => {
                return Err(Status::with_details(
                    tonic::Code::ResourceExhausted,
                    "RUNTIME_PROXY_BUSY",
                    b"DETAIL_CANARY".as_slice().into(),
                ));
            }
            _ => {}
        }
        Ok(Response::new(reply))
    }
}

#[test]
#[ignore = "explicit existing synthetic PKI required; no Docker or PG, never self-skip"]
fn actual_controller_network_busy_is_distinct_and_same_channel_can_recover() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, 4);
    let mut transport = Transport::new(fixture.config(&pki, pki::CONTROLLER)).unwrap();
    let input = request();
    let error = transport
        .inspect(&input, Instant::now(), LIMIT, &|| Ok(()))
        .unwrap_err();
    assert_eq!(
        error,
        InspectionFailure::Busy,
        "authenticated temporary contention must not become terminal refusal"
    );
    let reply = transport
        .inspect(&input, Instant::now(), LIMIT, &|| Ok(()))
        .unwrap();
    assert_eq!(reply, response(&input));
    assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), 2);
}

#[test]
#[ignore = "explicit existing synthetic PKI required; no Docker or PG, never self-skip"]
fn actual_controller_network_busy_cannot_mask_revocation_or_unrecognized_status() {
    let pki = pki::Pki::require();
    for mode in [5, 6, 7, 8, 9] {
        let fixture = Fixture::new(&pki, mode);
        let mut transport = Transport::new(fixture.config(&pki, pki::CONTROLLER)).unwrap();
        let check = || {
            if fixture.agent.current.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(unavailable())
            }
        };
        let error = transport
            .inspect(&request(), Instant::now(), LIMIT, &check)
            .unwrap_err();
        assert_eq!(
            error,
            InspectionFailure::Refused,
            "mode {mode} must remain terminal"
        );
        assert_eq!(
            format!("{error:?}"),
            "Refused",
            "peer data must remain redacted"
        );
    }
}
struct Fixture {
    endpoint: String,
    agent: Agent,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(pki: &pki::Pki, mode: usize) -> Self {
        crate::install_rustls_provider();
        let agent = Agent {
            pin: pki.pin(pki::CONTROLLER),
            calls: Arc::default(),
            mode,
            current: Arc::new(AtomicBool::new(true)),
        };
        let service = agent.clone();
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(false);
        let (ready, incoming) = mpsc::sync_channel(1);
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let input = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                ready.send(format!("https://{}", input.local_addr().unwrap())).unwrap();
                Server::builder().tls_config(tls).unwrap()
                    .add_service(proto::runtime_network_inspection_server::RuntimeNetworkInspectionServer::new(service)
                        .max_decoding_message_size(4096).max_encoding_message_size(4096))
                    .serve_with_incoming_shutdown(input, async { let _ = stopping.await; }).await.unwrap();
            });
        });
        Self {
            endpoint: incoming.recv_timeout(Duration::from_secs(5)).unwrap(),
            agent,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    fn config(&self, pki: &pki::Pki, peer: &str) -> RuntimeExecutionConfig {
        // Test-only config construction; production takes an owned loaded file
        // generation. Its file/ACL rechecks have separate config tests.
        let mut config = RuntimeExecutionConfig::ownership_test_value();
        config.installation_id = request().binding.unwrap().installation_id;
        config.scopes = vec![crate::ExactScope {
            workspace_id: "workspace".into(),
            namespace_id: "namespace".into(),
        }];
        config.endpoint = self.endpoint.clone();
        config.tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .identity(pki.identity("trusted-host", peer));
        config
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
#[ignore = "explicit existing synthetic PKI required; no Docker or PG, never self-skip"]
fn actual_controller_network_transport_preserves_binding_and_never_sends_workload_credentials() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, 0);
    let mut transport = Transport::new(fixture.config(&pki, pki::CONTROLLER)).unwrap();
    for _ in 0..2 {
        let input = request();
        assert_eq!(
            transport
                .inspect(&input, Instant::now(), LIMIT, &|| Ok(()))
                .unwrap(),
            response(&input)
        );
    }
    assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), 2);
    let mut bad = request();
    bad.binding
        .as_mut()
        .unwrap()
        .target
        .as_mut()
        .unwrap()
        .namespace_id = "other".into();
    assert!(
        transport
            .inspect(&bad, Instant::now(), LIMIT, &|| Ok(()))
            .is_err()
    );
    assert!(
        transport
            .inspect(&request(), Instant::now(), LIMIT, &|| Err(unavailable()))
            .is_err()
    );
    assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), 2);
}

#[test]
#[ignore = "explicit existing synthetic PKI required; no Docker or PG, never self-skip"]
fn actual_controller_network_transport_refuses_wrong_leaf_nonce_and_post_rpc_revocation() {
    let pki = pki::Pki::require();
    for (peer, mode, calls) in [
        (pki::OTHER, 0, 0),
        (pki::CONTROLLER, 1, 1),
        (pki::CONTROLLER, 3, 1),
    ] {
        let fixture = Fixture::new(&pki, mode);
        let mut transport = Transport::new(fixture.config(&pki, peer)).unwrap();
        let check = || {
            if fixture.agent.current.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(unavailable())
            }
        };
        assert!(
            transport
                .inspect(&request(), Instant::now(), LIMIT, &check)
                .is_err()
        );
        assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), calls);
    }
}

#[test]
#[ignore = "explicit existing synthetic PKI required; no Docker or PG, never self-skip"]
fn actual_controller_network_transport_uses_original_budget_and_cancels_wait() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, 2);
    let mut transport = Transport::new(fixture.config(&pki, pki::CONTROLLER)).unwrap();
    let started = Instant::now();
    assert!(
        transport
            .inspect(&request(), started, Duration::from_millis(150), &|| Ok(()))
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), 1);
    assert!(
        transport
            .inspect(&request(), started, Duration::from_millis(150), &|| Ok(()))
            .is_err()
    );
    assert_eq!(fixture.agent.calls.load(Ordering::SeqCst), 1);
}
