//! Real incoming mTLS using the existing PKI helper and generated launch artifact.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, ClientTlsConfig, Server, ServerTlsConfig, server::TcpIncoming},
};

pub(super) const INSTALLATION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1009";
#[derive(Clone, Copy)]
pub(super) enum Mode {
    Good,
    Mutate(fn(&mut proto::RuntimeHealthObservationResponse)),
    Hold,
    DelayedSample,
    PostCurrent,
    PostConfig,
    Status,
}

#[derive(Clone)]
struct Agent {
    pin: [u8; 32],
    requests: Arc<Mutex<Vec<proto::RuntimeHealthObservationRequest>>>,
    report: proto::ReadinessReport,
    mode: Mode,
    current: Arc<AtomicBool>,
    revoke: Arc<Mutex<Option<std::path::PathBuf>>>,
}
#[tonic::async_trait]
impl proto::runtime_health_observation_server::RuntimeHealthObservation for Agent {
    async fn observe(
        &self,
        request: Request<proto::RuntimeHealthObservationRequest>,
    ) -> Result<Response<proto::RuntimeHealthObservationResponse>, Status> {
        let peer = apex_auth::PeerIdentity::from_request(&request)
            .ok_or_else(|| Status::unauthenticated("missing peer"))?;
        if peer.certificate_sha256 != self.pin {
            return Err(Status::permission_denied("wrong peer"));
        }
        assert!(request.metadata().get("authorization").is_none());
        assert!(
            request
                .metadata()
                .get_bin("apex-instance-proof-bin")
                .is_none()
        );
        let timeout = request
            .metadata()
            .get("grpc-timeout")
            .unwrap()
            .to_str()
            .unwrap();
        let (amount, unit) = timeout.split_at(timeout.len() - 1);
        let amount: u64 = amount.parse().unwrap();
        let duration = match unit {
            "n" => Duration::from_nanos(amount),
            "u" => Duration::from_micros(amount),
            "m" => Duration::from_millis(amount),
            "S" => Duration::from_secs(amount),
            _ => panic!("health RPC must be capped at ten seconds"),
        };
        assert!(!duration.is_zero() && duration <= Duration::from_secs(10));
        self.requests
            .lock()
            .unwrap()
            .push(request.get_ref().clone());
        let mut reply = proto::RuntimeHealthObservationResponse {
            schema_version: 1,
            binding: request.get_ref().binding.clone(),
            nonce: request.get_ref().nonce.clone(),
            sample: Some(proto::RuntimeHealthSample {
                schema_version: 1,
                report: Some(self.report.clone()),
                valid_for_ns: 10_000_000_000,
            }),
        };
        match self.mode {
            Mode::Good => {}
            Mode::Mutate(change) => change(&mut reply),
            Mode::Hold => tokio::time::sleep(Duration::from_secs(1)).await,
            Mode::DelayedSample => {
                tokio::time::sleep(Duration::from_millis(40)).await;
                reply.sample.as_mut().unwrap().valid_for_ns = 200_000_999;
            }
            Mode::PostCurrent => self.current.store(false, Ordering::SeqCst),
            Mode::PostConfig => {
                std::fs::write(
                    self.revoke.lock().unwrap().as_ref().unwrap(),
                    b"changed-protected-config",
                )
                .unwrap();
            }
            Mode::Status => {
                return Err(Status::with_details(
                    tonic::Code::Unavailable,
                    "PEER_SECRET_CANARY",
                    b"PEER_DETAIL_CANARY".as_slice().into(),
                ));
            }
        }
        Ok(Response::new(reply))
    }
}
pub(super) struct Fixture {
    endpoint: String,
    pub requests: Arc<Mutex<Vec<proto::RuntimeHealthObservationRequest>>>,
    pub report: proto::ReadinessReport,
    pub current: Arc<AtomicBool>,
    pub revoke: Arc<Mutex<Option<std::path::PathBuf>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    pub fn new(pki: &pki::Pki, mode: Mode) -> Self {
        crate::install_rustls_provider();
        let (_, observed) = inputs();
        let launch = observed
            .runtime
            .unwrap()
            .launch_attestation
            .unwrap()
            .launch
            .unwrap();
        let report = report(&launch);
        let requests = Arc::default();
        let current = Arc::new(AtomicBool::new(true));
        let revoke = Arc::default();
        let agent = Agent {
            pin: pki.pin(pki::CONTROLLER),
            requests: Arc::clone(&requests),
            report: report.clone(),
            mode,
            current: Arc::clone(&current),
            revoke: Arc::clone(&revoke),
        };
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
                    .add_service(proto::runtime_health_observation_server::RuntimeHealthObservationServer::new(agent)
                        .max_decoding_message_size(4096).max_encoding_message_size(65536))
                    .serve_with_incoming_shutdown(input, async { let _ = stopping.await; }).await.unwrap();
            });
        });
        Self {
            endpoint: incoming.recv_timeout(Duration::from_secs(5)).unwrap(),
            requests,
            report,
            current,
            revoke,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    pub fn config(&self, pki: &pki::Pki, peer: &str) -> RuntimeExecutionConfig {
        let mut config = RuntimeExecutionConfig::ownership_test_value();
        config.installation_id = INSTALLATION.into();
        config.scopes = vec![crate::ExactScope {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
        }];
        config.endpoint = self.endpoint.clone();
        config.tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .identity(pki.identity("trusted-host", peer));
        config
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
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

pub(super) fn inputs() -> (
    proto::RuntimeReconcileRequest,
    proto::RuntimeReconcileResponse,
) {
    let path = std::path::PathBuf::from(
        std::env::var_os("APEX_RUNTIME_FIXTURE_PATH")
            .expect("generated task-1-parity runtime fixture required"),
    );
    let config: proto::RuntimeConfiguration =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let launch: proto::RuntimeLaunchContext =
        serde_json::from_slice(&std::fs::read(path.with_file_name("launch-context.json")).unwrap())
            .unwrap();
    assert_eq!(config.runtime_manifest_hash, launch.runtime_manifest_hash);
    let mut request = proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: launch.target.clone(),
        config_hash: launch.config_hash.clone(),
        operation_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1010".into(),
        command_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1011".into(),
    };
    request.target.as_mut().unwrap().fencing_token += 2;
    let response = proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::NotServing.into(),
        runtime: Some(proto::RuntimeObservation {
            target: launch.target.clone(),
            runtime_id: "a".repeat(64),
            state: "not-serving".into(),
            observed_at_unix_us: 1,
            launch_attestation: Some(proto::RuntimeLaunchAttestation {
                schema_version: 1,
                installation_id: INSTALLATION.into(),
                launch: Some(launch),
                instance_proof_sha256: "d".repeat(64),
                staged_manifest_sha256: "e".repeat(64),
                image_id: format!("sha256:{}", "f".repeat(64)),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    (request, response)
}

fn report(launch: &proto::RuntimeLaunchContext) -> proto::ReadinessReport {
    let names = [
        "config",
        "launch",
        "material",
        "inbound_auth",
        "upstream_catalog",
        "governance",
        "evidence_admission",
        "network",
        "admission",
    ];
    proto::ReadinessReport {
        live: true,
        ready: true,
        target: launch.target.clone(),
        observed_at_unix_us: 9_007_199_254_740_993,
        config_hash: launch.config_hash.clone(),
        runtime_manifest_hash: launch.runtime_manifest_hash.clone(),
        process_instance_id: launch.process_instance_id.clone(),
        launch_context_hash: launch.launch_context_hash.clone(),
        checks: (1..=9)
            .map(|id| proto::ReadinessCheck {
                id,
                status: proto::ReadinessCheckStatus::Pass.into(),
                reason: proto::ReadinessReason::Ok.into(),
            })
            .collect(),
        stages: names
            .into_iter()
            .map(|name| proto::ProxyStageTiming {
                name: format!("readiness.{name}"),
                started_at_unix_us: 9_007_199_254_740_993,
                duration_ns: Some(9_007_199_254_740_993),
                duration_us: 9_007_199_254_740,
                clock_resolution_ns: 1,
                clock_source: "test-monotonic".into(),
                process_instance_id: launch.process_instance_id.clone(),
                ..Default::default()
            })
            .collect(),
    }
}
