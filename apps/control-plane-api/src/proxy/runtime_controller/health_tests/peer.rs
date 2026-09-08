use super::*;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Server, ServerTlsConfig, server::TcpIncoming},
};

#[derive(Clone)]
struct Agent {
    observed: proto::RuntimeObservation,
    pin: [u8; 32],
    calls: Arc<Mutex<Vec<&'static str>>>,
    unavailable: bool,
}
impl Agent {
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if apex_auth::PeerIdentity::from_request(request)
            .is_none_or(|p| p.certificate_sha256 != self.pin)
        {
            return Err(Status::permission_denied("peer"));
        }
        Ok(())
    }
}
#[tonic::async_trait]
impl proto::runtime_execution_service_server::RuntimeExecutionService for Agent {
    async fn reconcile_runtime(
        &self,
        request: Request<proto::RuntimeReconcileRequest>,
    ) -> Result<Response<proto::RuntimeReconcileResponse>, Status> {
        self.authenticate(&request)?;
        self.calls.lock().unwrap().push("reconcile");
        Ok(Response::new(proto::RuntimeReconcileResponse {
            schema_version: 1,
            claims: Some(request.into_inner()),
            observed_state: proto::ProxyObservedState::NotServing as i32,
            runtime: Some(self.observed.clone()),
            error_code: self.observed.error_code.clone(),
        }))
    }
}
#[tonic::async_trait]
impl proto::runtime_health_observation_server::RuntimeHealthObservation for Agent {
    async fn observe(
        &self,
        request: Request<proto::RuntimeHealthObservationRequest>,
    ) -> Result<Response<proto::RuntimeHealthObservationResponse>, Status> {
        self.authenticate(&request)?;
        self.calls.lock().unwrap().push("health");
        if self.unavailable {
            return Err(Status::unavailable("synthetic health unavailable"));
        }
        let request = request.into_inner();
        let launch = self
            .observed
            .launch_attestation
            .as_ref()
            .unwrap()
            .launch
            .as_ref()
            .unwrap();
        let binding = proto::ManagedDeploymentBinding {
            installation_id: self
                .observed
                .launch_attestation
                .as_ref()
                .unwrap()
                .installation_id
                .clone(),
            target: launch.target.clone(),
            process_instance_id: launch.process_instance_id.clone(),
            config_hash: launch.config_hash.clone(),
            launch_context_hash: launch.launch_context_hash.clone(),
        };
        assert_eq!(request.binding.as_ref(), Some(&binding));
        assert_eq!(request.nonce.len(), 32);
        let report = proto::ReadinessReport {
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
                    status: 2,
                    reason: 1,
                })
                .collect(),
            stages: [
                "config",
                "launch",
                "material",
                "inbound_auth",
                "upstream_catalog",
                "governance",
                "evidence_admission",
                "network",
                "admission",
            ]
            .into_iter()
            .map(|name| proto::ProxyStageTiming {
                name: format!("readiness.{name}"),
                started_at_unix_us: 9_007_199_254_740_993,
                duration_us: 1,
                duration_ns: Some(1_999),
                clock_source: "synthetic-monotonic".into(),
                clock_resolution_ns: 1,
                process_instance_id: launch.process_instance_id.clone(),
                ..Default::default()
            })
            .collect(),
        };
        Ok(Response::new(proto::RuntimeHealthObservationResponse {
            schema_version: 1,
            binding: Some(binding),
            nonce: request.nonce,
            sample: Some(proto::RuntimeHealthSample {
                schema_version: 1,
                report: Some(report),
                valid_for_ns: 5_000_000_999,
            }),
        }))
    }
}

pub(super) struct Peer {
    pub config: RuntimeExecutionConfig,
    pub observed: proto::RuntimeObservation,
    pub calls: Arc<Mutex<Vec<&'static str>>>,
    base: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Peer {
    pub fn new(f: &mut fixture::Fixture, unavailable: bool) -> Self {
        crate::install_rustls_provider();
        let pki = pki::Pki::require();
        let artifact = PathBuf::from(
            std::env::var_os("APEX_RUNTIME_FIXTURE_PATH")
                .expect("generated runtime fixture required"),
        );
        let mut launch: proto::RuntimeLaunchContext = serde_json::from_slice(
            &fs::read(artifact.with_file_name("launch-context.json")).unwrap(),
        )
        .unwrap();
        let b = &mut f.registration.binding;
        launch.target = b.target.clone();
        launch.config_hash = b.config_hash.clone();
        launch.runtime_manifest_hash = f.registration.configuration.runtime_manifest_hash.clone();
        launch.process_instance_id = b.process_instance_id.clone();
        let mut json = serde_json::to_value(&launch).unwrap();
        json.as_object_mut().unwrap().remove("launchContextHash");
        sort(&mut json);
        launch.launch_context_hash =
            format!("{:x}", Sha256::digest(serde_json::to_vec(&json).unwrap()));
        b.launch_context_hash = launch.launch_context_hash.clone();
        let observed = proto::RuntimeObservation {
            target: b.target.clone(),
            runtime_id: "a".repeat(64),
            state: "not-serving".into(),
            observed_at_unix_us: 1,
            error_code: "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE".into(),
            launch_attestation: Some(proto::RuntimeLaunchAttestation {
                schema_version: 1,
                installation_id: b.installation_id.clone(),
                launch: Some(launch),
                instance_proof_sha256: "07".repeat(32),
                staged_manifest_sha256: "e".repeat(64),
                image_id: format!("sha256:{}", "f".repeat(64)),
            }),
            ..Default::default()
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let agent = Agent {
            observed: observed.clone(),
            pin: pki.pin(pki::CONTROLLER),
            calls: Arc::clone(&calls),
            unavailable,
        };
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(false);
        let (ready, endpoint) = mpsc::sync_channel(1);
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                ready.send(format!("https://{}", incoming.local_addr().unwrap())).unwrap();
                Server::builder().tls_config(tls).unwrap()
                    .add_service(proto::runtime_execution_service_server::RuntimeExecutionServiceServer::new(agent.clone()))
                    .add_service(proto::runtime_health_observation_server::RuntimeHealthObservationServer::new(agent))
                    .serve_with_incoming_shutdown(incoming, async { let _ = stopping.await; }).await.unwrap();
            });
        });
        let parent = std::env::var_os("APEX_HEALTH_TEST_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| artifact.parent().unwrap().parent().unwrap().to_owned());
        let base = parent.join(format!("health-consumption-test-{}", Uuid::now_v7()));
        fs::create_dir(&base).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (file, source) in [
            ("ca.pem", "ca.pem"),
            ("client.pem", "control-operator-client.pem"),
            ("client.key", "control-operator-client.key"),
        ] {
            write(&base.join(file), &pki.read("trusted-host", source));
        }
        let target = b.target.as_ref().unwrap();
        write(&base.join("execution.json"), &serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"installation_id":b.installation_id,"worker_id":"controller-a",
            "endpoint":endpoint.recv_timeout(Duration::from_secs(5)).unwrap(),"server_name":"control-plane-api",
            "ca_file":"ca.pem","client_cert_file":"client.pem","client_key_file":"client.key",
            "scopes":[{"workspace_id":target.workspace_id,"namespace_id":target.namespace_id}]
        })).unwrap());
        let config = RuntimeExecutionConfig::load(&base, &base.join("execution.json")).unwrap();
        Self {
            config,
            observed,
            calls,
            base,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    pub fn prepare(&self, f: &fixture::Fixture) {
        f.store
            .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
            .unwrap();
        let request = proto::ManagedDeploymentRenewal {
            binding: Some(f.registration.binding.clone()),
            nonce: vec![1; 32],
            renewal_sequence: 1,
            applied: None,
        };
        let grant = f
            .store
            .renew_deployment_checked(&request, &|| Ok(()))
            .unwrap();
        f.store
            .renew_deployment_checked(
                &proto::ManagedDeploymentRenewal {
                    renewal_sequence: 2,
                    applied: Some(proto::ManagedGrantAcknowledgement {
                        decision_id: grant.decision_id,
                        epoch: grant.epoch,
                        admitting: false,
                        active_calls: 0,
                    }),
                    ..request
                },
                &|| Ok(()),
            )
            .unwrap();
    }
}
fn write(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn sort(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            fields.sort_keys();
            for value in fields.values_mut() {
                sort(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sort(value);
            }
        }
        _ => {}
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        for file in ["execution.json", "ca.pem", "client.pem", "client.key"] {
            let _ = fs::remove_file(self.base.join(file));
        }
        let _ = fs::remove_dir(&self.base);
    }
}
