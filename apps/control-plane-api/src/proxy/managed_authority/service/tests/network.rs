//! Actual workload->CP->Controller TLS, protected files and PG eligibility.
//! The agent's confinement reply is synthetic; real engine proof is separate.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone)]
struct Agent {
    pin: [u8; 32],
    calls: Arc<AtomicUsize>,
    confined: Arc<AtomicBool>,
    refusal: Arc<AtomicUsize>,
}
#[tonic::async_trait]
impl proto::runtime_network_inspection_server::RuntimeNetworkInspection for Agent {
    async fn check(
        &self,
        request: Request<proto::RuntimeNetworkInspectionRequest>,
    ) -> Result<Response<proto::RuntimeNetworkInspectionResponse>, Status> {
        let peer = apex_auth::PeerIdentity::from_request(&request).unwrap();
        assert_eq!(peer.certificate_sha256, self.pin);
        assert!(request.metadata().get("authorization").is_none());
        assert!(
            request
                .metadata()
                .get_bin("apex-instance-proof-bin")
                .is_none()
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.refusal.load(Ordering::SeqCst) {
            1 => return Err(Status::resource_exhausted("RUNTIME_PROXY_BUSY")),
            2 => return Err(Status::resource_exhausted("RUNTIME_NETWORK_BUSY")),
            3 => return Err(Status::resource_exhausted("RUNTIME_OVERLOADED")),
            4 => return Err(Status::permission_denied("RUNTIME_PROXY_BUSY")),
            5 => return Err(Status::unavailable("RUNTIME_PROXY_BUSY")),
            _ => {}
        }
        let input = request.into_inner();
        Ok(Response::new(proto::RuntimeNetworkInspectionResponse {
            schema_version: 1,
            binding: input.binding,
            nonce: input.nonce,
            network_binding_sha256: "c".repeat(64),
            gateway_process_sha256: "d".repeat(64),
            guard_process_sha256: "e".repeat(64),
            valid_for_us: 10_000_000,
            confined: self.confined.load(Ordering::SeqCst),
        }))
    }
}

fn probe(
    binding: &proto::ManagedDeploymentBinding,
) -> Request<proto::RuntimeNetworkInspectionRequest> {
    let (metadata, _, _) = request(binding, 1).into_parts();
    Request::from_parts(
        metadata,
        tonic::Extensions::new(),
        proto::RuntimeNetworkInspectionRequest {
            schema_version: 1,
            binding: Some(binding.clone()),
            nonce: vec![9; 32],
        },
    )
}

#[test]
#[ignore = "explicit fresh Linux PKI/Postgres fixture; never self-skip"]
fn actual_managed_network_relay_authenticates_both_hops_and_preserves_nonadmitting_state() {
    crate::install_rustls_provider();
    let pki = pki::Pki::require();
    let mut f = fixture::Fixture::new();
    f.registration.proof_sha256 = Sha256::digest([7; 32]).into();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let binding = f.registration.binding.clone();
    let target = binding.target.as_ref().unwrap();
    let before = f
        .store
        .read_deployment_checked(&binding, &|| Ok(()))
        .unwrap();
    let base = PathBuf::from(
        std::env::var_os("APEX_MANAGED_POLICY_TEST_BASE").expect("private fixture required"),
    )
    .join(Uuid::now_v7().to_string());
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let profile = base.join("managed.json");
    let document = serde_json::json!({"schema_version":1,"version":"v1","valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807",
        "profiles":[{"installation_id":binding.installation_id,"workspace_id":target.workspace_id,"namespace_id":target.namespace_id,
        "proxy_id":target.proxy_id,"revision_id":target.revision_id,"authority_profile_ref":f.registration.authority_profile_ref,
        "authority_profile_version":f.registration.authority_profile_version,"evidence_agent_id":"managed-component-proxy",
        "credentials":[{"certificate_sha256":pki::hex(&pki.pin(pki::OTHER)),"token_sha256":format!("{:x}",Sha256::digest(b"managed-test-token-123"))}]}]});
    fs::write(&profile, serde_json::to_vec(&document).unwrap()).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let agent = Agent {
        pin: pki.pin(pki::CONTROLLER),
        calls: Arc::default(),
        confined: Arc::new(AtomicBool::new(true)),
        refusal: Arc::default(),
    };
    let input =
        runtime.block_on(async { TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap() });
    let endpoint = format!("https://{}", input.local_addr().unwrap());
    let (stop_agent, stopping_agent) = tokio::sync::oneshot::channel();
    let agent_service = agent.clone();
    let agent_tls = ServerTlsConfig::new()
        .identity(pki.identity("trusted-host", "control-plane-server"))
        .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .client_auth_optional(false);
    let agent_server = runtime.spawn(async move {
        Server::builder()
            .tls_config(agent_tls)
            .unwrap()
            .add_service(
                proto::runtime_network_inspection_server::RuntimeNetworkInspectionServer::new(
                    agent_service,
                ),
            )
            .serve_with_incoming_shutdown(input, async {
                let _ = stopping_agent.await;
            })
            .await
            .unwrap();
    });
    for (file, original) in [
        ("ca.pem", "ca.pem"),
        ("controller.pem", "control-operator-client.pem"),
        ("controller.key", "control-operator-client.key"),
    ] {
        let path = base.join(file);
        fs::write(&path, pki.read("trusted-host", original)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config_file = base.join("execution.json");
    let config = serde_json::json!({"schema_version":1,"installation_id":binding.installation_id,"worker_id":"network-relay-test",
        "endpoint":endpoint,"server_name":"control-plane-api","ca_file":base.join("ca.pem"),
        "client_cert_file":base.join("controller.pem"),"client_key_file":base.join("controller.key"),
        "scopes":[{"workspace_id":target.workspace_id,"namespace_id":target.namespace_id}]});
    fs::write(&config_file, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let config = crate::RuntimeExecutionConfig::load(&base, &config_file).unwrap();
    let execution = crate::RuntimeExecutionOwner::new(config, &f.url).unwrap();
    let policy = GovernanceConfig::new(
        ["northstar-401k"],
        ["workspace/namespace"],
        "ria-read-v1",
        9_007_199_254_740_993,
        ["client.tax_id"],
    )
    .unwrap();
    let mut owner =
        crate::ManagedAuthorityOwner::new(profile, base.clone(), &f.url, policy).unwrap();
    owner.configure_network_inspection(&execution).unwrap();
    assert!(owner.configure_network_inspection(&execution).is_err());
    let service = owner.start().unwrap();
    assert!(owner.configure_network_inspection(&execution).is_err());
    runtime.block_on(async {
        let input = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", input.local_addr().unwrap());
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(false);
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(crate::bounded_managed_network_readiness_server(service))
                .serve_with_incoming_shutdown(input, async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let channel = Endpoint::from_shared(endpoint)
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("control-plane-api")
                    .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
                    .identity(pki.identity("trusted-host", pki::OTHER)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client =
            proto::managed_network_readiness_client::ManagedNetworkReadinessClient::new(channel);
        let reply = client.check(probe(&binding)).await.unwrap().into_inner();
        assert_eq!(reply.binding, Some(binding.clone()));
        assert_eq!(reply.nonce, vec![9; 32]);
        assert!(reply.confined);
        assert_eq!(agent.calls.load(Ordering::SeqCst), 1);
        for mode in 1..=5 {
            agent.refusal.store(mode, Ordering::SeqCst);
            let refusal = client.check(probe(&binding)).await.unwrap_err();
            assert_eq!(
                refusal.code(),
                if mode <= 3 {
                    tonic::Code::ResourceExhausted
                } else {
                    tonic::Code::PermissionDenied
                }
            );
            assert_eq!(
                refusal.message(),
                if mode <= 3 {
                    "MANAGED_NETWORK_BUSY"
                } else {
                    "MANAGED_AUTHORITY_REFUSED"
                }
            );
            assert!(refusal.details().is_empty());
        }
        agent.refusal.store(0, Ordering::SeqCst);
        let recovered = client.check(probe(&binding)).await.unwrap().into_inner();
        assert_eq!(recovered.binding, Some(binding.clone()));
        assert_eq!(recovered.nonce, vec![9; 32]);
        assert!(recovered.confined);
        let accepted_calls = agent.calls.load(Ordering::SeqCst);
        assert_eq!(accepted_calls, 7);
        for bad in 0..4 {
            let mut input = probe(&binding);
            match bad {
                0 => {
                    input.metadata_mut().remove("authorization");
                }
                1 => {
                    input.metadata_mut().insert_bin(
                        "apex-instance-proof-bin",
                        MetadataValue::from_bytes(&[6; 32]),
                    );
                }
                2 => {
                    input
                        .get_mut()
                        .binding
                        .as_mut()
                        .unwrap()
                        .process_instance_id = Uuid::now_v7().to_string();
                }
                3 => {
                    input
                        .get_mut()
                        .binding
                        .as_mut()
                        .unwrap()
                        .target
                        .as_mut()
                        .unwrap()
                        .namespace_id = "other".into();
                }
                _ => unreachable!(),
            }
            assert!(client.check(input).await.is_err());
            assert_eq!(
                agent.calls.load(Ordering::SeqCst),
                accepted_calls,
                "invalid workload must not reach agent"
            );
        }
        agent.confined.store(false, Ordering::SeqCst);
        assert!(client.check(probe(&binding)).await.is_err());
        assert_eq!(agent.calls.load(Ordering::SeqCst), accepted_calls + 1);
        drop(client);
        stop.send(()).unwrap();
        server.await.unwrap();
    });
    owner.request_shutdown();
    owner.shutdown().unwrap();
    stop_agent.send(()).unwrap();
    runtime.block_on(agent_server).unwrap();
    let after = f
        .store
        .read_deployment_checked(&binding, &|| Ok(()))
        .unwrap();
    assert_eq!(after.mode, before.mode);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.highest_sequence, before.highest_sequence);
    assert_eq!(after.active_calls, before.active_calls);
    assert!(after.applied.is_none());
}
