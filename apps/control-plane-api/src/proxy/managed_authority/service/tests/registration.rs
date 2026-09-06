//! Actual enrolled agent TLS -> publication resolution -> durable registration.
//! Attestation is fixture metadata here, not an agent engine/staging proof.
use super::*;
use crate::{RuntimeAuthorityOwner, RuntimeAuthorityPolicyFiles};
mod fixture_data;
mod revocation;

#[test]
#[ignore = "requires explicit private Linux/PKI/PostgreSQL fixtures; run with --ignored"]
fn actual_agent_registration_preserves_transport_and_registers_only_enrolled_launch() {
    crate::install_rustls_provider();
    let pki = pki::Pki::require();
    let mut f = fixture::Fixture::new();
    f.registration.proof_sha256 = Sha256::digest([7; 32]).into();
    let base = PathBuf::from(std::env::var_os("APEX_MANAGED_POLICY_TEST_BASE").unwrap())
        .join(Uuid::now_v7().to_string());
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let mut data = fixture_data::prepare(&f, &pki, &base);
    let files = RuntimeAuthorityPolicyFiles::new(
        base.clone(),
        base.join("peer.json"),
        base.join("enrollment.json"),
    )
    .unwrap()
    .with_deployment_bindings_file(base.join("deployment.json"))
    .unwrap();
    let mut authority_owner = RuntimeAuthorityOwner::new(files, &f.url).unwrap();
    let authority = authority_owner.start().unwrap();
    let policy = GovernanceConfig::new(
        ["northstar-401k"],
        ["workspace/namespace"],
        "ria-read-v1",
        1,
        ["client.tax_id"],
    )
    .unwrap();
    let mut managed_owner = Owner::new().unwrap();
    let managed = managed_owner
        .start(base.join("managed.json"), base.clone(), &f.url, policy)
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let (shutdown, stopping) = tokio::sync::oneshot::channel();
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(false);
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(crate::bounded_runtime_deployment_service_server(
                    authority.clone(),
                ))
                .add_service(crate::bounded_runtime_deployment_registry_server(
                    authority,
                    managed.clone(),
                ))
                .add_service(crate::bounded_managed_runtime_authority_server(managed))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let channel = fixture_data::channel(&pki, &endpoint, pki::AGENT).await;
        let mut resolution =
            proto::runtime_deployment_service_client::RuntimeDeploymentServiceClient::new(
                channel.clone(),
            );
        let resolved = resolution
            .resolve_runtime_deployment(data.authority.clone().unwrap())
            .await
            .unwrap()
            .into_inner();
        // Build immutable launch from the independently compiled actual reply.
        let config = resolved.configuration.unwrap();
        let launch = data.attestation.as_mut().unwrap().launch.as_mut().unwrap();
        launch.runtime_manifest_hash = config.runtime_manifest_hash.clone();
        fixture_data::seal(launch);
        let mut registry =
            proto::runtime_deployment_registry_client::RuntimeDeploymentRegistryClient::new(
                channel,
            );
        for role in [pki::CONTROLLER, pki::OTHER] {
            let mut wrong =
                proto::runtime_deployment_registry_client::RuntimeDeploymentRegistryClient::new(
                    fixture_data::channel(&pki, &endpoint, role).await,
                );
            assert!(
                wrong.register_deployment(data.clone()).await.is_err(),
                "wrong role {role}"
            );
        }
        // All mismatches precede first registration; no existing-byte conflict
        // can mask a broken profile or current-operation check.
        for bad in 0..5 {
            let mut wrong = data.clone();
            match bad {
                0 => {
                    wrong
                        .authority
                        .as_mut()
                        .unwrap()
                        .observed_controller_certificate_sha256 = pki.pin(pki::OTHER).to_vec()
                }
                1 => {
                    wrong
                        .authority
                        .as_mut()
                        .unwrap()
                        .target
                        .as_mut()
                        .unwrap()
                        .fencing_token += 1
                }
                2 => {
                    wrong.attestation.as_mut().unwrap().image_id =
                        format!("sha256:{}", "e".repeat(64))
                }
                3 => {
                    let launch = wrong.attestation.as_mut().unwrap().launch.as_mut().unwrap();
                    launch.materials.swap(0, 1);
                    fixture_data::seal(launch);
                }
                _ => wrong.attestation.as_mut().unwrap().instance_proof_sha256 = "bad".into(),
            }
            assert!(
                registry.register_deployment(wrong).await.is_err(),
                "bad {bad}"
            );
        }
        let receipt = registry
            .register_deployment(data.clone())
            .await
            .unwrap()
            .into_inner();
        let expected = data.attestation.as_ref().unwrap();
        assert_eq!(
            receipt.attestation_sha256,
            format!("{:x}", Sha256::digest(expected.encode_to_vec()))
        );
        let retry = registry
            .register_deployment(data.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(retry.binding, receipt.binding);
        assert_eq!(retry.attestation_sha256, receipt.attestation_sha256);
        assert!(
            retry.authority.as_ref().unwrap().checked_at_unix_us
                >= receipt.authority.as_ref().unwrap().checked_at_unix_us
        );
        let binding = receipt.binding.unwrap();
        assert_eq!(
            binding.launch_context_hash,
            expected.launch.as_ref().unwrap().launch_context_hash
        );
        let mut workload =
            proto::managed_runtime_authority_client::ManagedRuntimeAuthorityClient::new(
                fixture_data::channel(&pki, &endpoint, pki::OTHER).await,
            );
        let grant = workload
            .renew_deployment(request(&binding, 1))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(grant.mode, proto::ManagedGrantMode::Prepare as i32);
        assert!((1..=10_000_000).contains(&grant.valid_for_us));
        revocation::during_insert(&f, &authority_owner, &mut registry, &data).await;
        assert!(registry.register_deployment(data).await.is_err());
        drop(registry);
        drop(resolution);
        drop(workload);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    });
    drop(runtime);
    assert!(authority_owner.shutdown().cleanup_complete);
    managed_owner.shutdown().unwrap();
    let mut client = f.client();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM mcp_proxy_deployment_attestations",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        client
            .query_one("SELECT mode,admitting FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, i32>(0),
        1
    );
    assert!(
        !client
            .query_one("SELECT admitting FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, bool>(0)
    );
    for name in [
        "peer.json",
        "enrollment.json",
        "deployment.json",
        "managed.json",
    ] {
        fs::remove_file(base.join(name)).unwrap();
    }
    fs::remove_dir(base).unwrap();
}
