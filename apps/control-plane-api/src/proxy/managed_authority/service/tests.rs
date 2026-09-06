//! Actual TLS + protected refresh + PostgreSQL service, with explicitly seeded
//! registry metadata. This is not production agent-to-registration attestation.
use super::*;
use crate::{LeasedProxyOperation, proxy::store::DeploymentRegistration};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt};
use tonic::{
    metadata::MetadataValue,
    transport::{
        Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig, server::TcpIncoming,
    },
};
use uuid::Uuid;

mod business;
#[allow(dead_code)]
#[allow(
    clippy::duplicate_mod,
    reason = "Reuse the exact metadata-only PostgreSQL fixture without widening production visibility"
)]
#[path = "../../store/postgres/serving/tests/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../../../../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
mod registration;

fn request(
    binding: &proto::ManagedDeploymentBinding,
    sequence: u64,
) -> Request<proto::ManagedDeploymentRenewal> {
    let mut request = Request::new(proto::ManagedDeploymentRenewal {
        binding: Some(binding.clone()),
        nonce: vec![8; 32],
        renewal_sequence: sequence,
        applied: None,
    });
    request.metadata_mut().insert(
        "authorization",
        "Bearer managed-test-token-123".parse().unwrap(),
    );
    request.metadata_mut().insert_bin(
        "apex-instance-proof-bin",
        MetadataValue::from_bytes(&[7; 32]),
    );
    request
}

#[test]
#[ignore = "requires explicit private Linux/PKI/PostgreSQL fixtures; run with --ignored"]
fn actual_managed_mtls_profile_proof_registry_and_same_channel_revocation() {
    crate::install_rustls_provider();
    let pki = pki::Pki::require();
    let mut f = fixture::Fixture::new();
    f.registration.proof_sha256 = Sha256::digest([7; 32]).into();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let binding = f.registration.binding.clone();
    let target = binding.target.as_ref().unwrap();
    let base = PathBuf::from(
        std::env::var_os("APEX_MANAGED_POLICY_TEST_BASE").expect("private fixture required"),
    )
    .join(Uuid::now_v7().to_string());
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let path = base.join("managed.json");
    let document = serde_json::json!({"schema_version":1,"version":"v1","valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807",
        "profiles":[{"installation_id":binding.installation_id,"workspace_id":target.workspace_id,"namespace_id":target.namespace_id,
        "proxy_id":target.proxy_id,"revision_id":target.revision_id,"authority_profile_ref":f.registration.authority_profile_ref,
        "authority_profile_version":f.registration.authority_profile_version,"evidence_agent_id":"managed-component-proxy",
        "credentials":[{"certificate_sha256":pki::hex(&pki.pin(pki::OTHER)),"token_sha256":format!("{:x}",Sha256::digest(b"managed-test-token-123"))}]}]});
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let policy = GovernanceConfig::new(
        ["northstar-401k"],
        ["workspace/namespace"],
        "ria-read-v1",
        9_007_199_254_740_993,
        ["client.tax_id"],
    )
    .unwrap();
    let mut owner = Owner::new().unwrap();
    let service = owner
        .start(path.clone(), base.clone(), &f.url, policy)
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
                .add_service(
                    proto::managed_proxy_governance_server::ManagedProxyGovernanceServer::new(
                        service.clone(),
                    )
                    .max_decoding_message_size(65_536)
                    .max_encoding_message_size(65_536),
                )
                .add_service(
                    proto::managed_runtime_authority_server::ManagedRuntimeAuthorityServer::new(
                        service,
                    )
                    .max_decoding_message_size(65_536)
                    .max_encoding_message_size(65_536),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let channel = Endpoint::from_shared(endpoint.clone())
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
            proto::managed_runtime_authority_client::ManagedRuntimeAuthorityClient::new(
                channel.clone(),
            );
        let mut governance =
            proto::managed_proxy_governance_client::ManagedProxyGovernanceClient::new(channel);
        let grant = client
            .renew_deployment(request(&binding, 1))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(grant.binding, Some(binding.clone()));
        assert_eq!(grant.mode, proto::ManagedGrantMode::Prepare as i32);
        assert!((1..=10_000_000).contains(&grant.valid_for_us));
        let (metadata, _, _) = request(&binding, 2).into_parts();
        let policy_request = Request::from_parts(
            metadata,
            tonic::Extensions::new(),
            proto::ManagedPolicyRequest {
                binding: Some(binding.clone()),
                nonce: vec![4; 32],
            },
        );
        let snapshot = client
            .get_managed_policy(policy_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(snapshot.binding, Some(binding.clone()));
        assert_eq!(snapshot.nonce, vec![4; 32]);
        assert_eq!(snapshot.policy_id, "ria-read-v1");
        assert_eq!(snapshot.revision, 9_007_199_254_740_993);
        assert_eq!(snapshot.field_restrictions, ["client.tax_id"]);
        business::exercise(&mut client, &mut governance, &f, &binding, &grant).await;
        // Business setup acknowledged sequences2..4. Every auth negative must
        // use an otherwise valid fresh body, not a changed-body replay refusal.
        client.renew_deployment(request(&binding, 5)).await.unwrap();
        for bad in 0..4 {
            let mut request = request(&binding, 6);
            match bad {
                0 => {
                    request.metadata_mut().insert_bin(
                        "apex-instance-proof-bin",
                        MetadataValue::from_bytes(&[9; 32]),
                    );
                }
                1 => {
                    request.metadata_mut().append(
                        "authorization",
                        "Bearer managed-test-token-123".parse().unwrap(),
                    );
                }
                2 => {
                    request
                        .get_mut()
                        .binding
                        .as_mut()
                        .unwrap()
                        .launch_context_hash = "c".repeat(64)
                }
                3 => {
                    request.metadata_mut().insert(
                        "authorization",
                        "Bearer foreign-test-token-123".parse().unwrap(),
                    );
                }
                _ => unreachable!(),
            }
            assert!(client.renew_deployment(request).await.is_err(), "bad {bad}");
        }
        let channel = Endpoint::from_shared(endpoint)
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("control-plane-api")
                    .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
                    .identity(pki.identity("trusted-host", pki::CONTROLLER)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut controller =
            proto::managed_runtime_authority_client::ManagedRuntimeAuthorityClient::new(channel);
        assert!(
            controller
                .renew_deployment(request(&binding, 6))
                .await
                .is_err()
        );
        // Matching positive control demonstrates the negative body itself is
        // still admissible with valid transport credentials and proof.
        client.renew_deployment(request(&binding, 6)).await.unwrap();
        // File mutation is fixture-owner work, never synchronous service-handler I/O.
        tokio::task::block_in_place(|| fs::write(&path, b"invalid replacement").unwrap());
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            if owner.refresh.shared.current().is_err() {
                break;
            }
            assert!(Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(client.renew_deployment(request(&binding, 7)).await.is_err());
        drop(client);
        drop(controller);
        drop(governance);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    });
    drop(runtime);
    owner.shutdown().unwrap();
    fs::remove_file(path).unwrap();
    fs::remove_dir(base).unwrap();
}
