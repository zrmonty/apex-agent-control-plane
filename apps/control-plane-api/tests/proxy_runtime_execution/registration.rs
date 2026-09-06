//! Actual production agent staging/callback and CP registry; no Serving artifact.
use crate::{
    fixture::*,
    journey, pki,
    process::{self, Process},
};
use apex_control_plane_api::proto::{self, mcp_proxy_service_client::McpProxyServiceClient};
use prost::Message;
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[path = "registration/configuration.rs"]
pub(super) mod configuration;

#[test]
fn actual_joint_sealed_stage_registers_original_proof_and_obtains_only_prepare() {
    let f = Fixture::for_registration();
    eprintln!("registration joint evidence root: {}", f.root.display());
    let mut cp = Process::control_registration(&f);
    let mut agent = Process::agent(&f);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let operation = runtime.block_on(async {
        let mut client =
            McpProxyServiceClient::new(process::channel(&f, f.cp, pki::CONTROLLER).await);
        let p = &f.proxies[0];
        let spec = client
            .get_proxy(process::operator(proto::GetProxyRequest {
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .proxy
            .unwrap()
            .spec;
        client
            .validate_proxy(process::operator(proto::ValidateProxyRequest {
                request_id: Uuid::now_v7().to_string(),
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
                expected_revision_id: Some(p.revision.revision_id.to_string()),
                draft: spec,
            }))
            .await
            .unwrap();
        client
            .deploy_proxy(process::operator(proto::DeployProxyRequest {
                request_id: Uuid::now_v7().to_string(),
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
                revision_id: p.revision.revision_id.to_string(),
                expected_revision_id: Some(p.revision.revision_id.to_string()),
            }))
            .await
            .unwrap()
            .into_inner()
            .operation
            .unwrap()
    });
    let response = journey::wait_dormant(&f, 0, &operation, 0);
    let observed = response.runtime.unwrap();
    journey::dormant(&observed.runtime_id);
    let expected = observed.launch_attestation.unwrap();
    let id = Uuid::parse_str(&expected.launch.as_ref().unwrap().process_instance_id).unwrap();
    let row = f.database.client().query_opt("SELECT a.attestation_bytes,d.binding_bytes FROM mcp_proxy_deployment_attestations a JOIN mcp_proxy_deployments d USING(instance_id) WHERE instance_id=$1", &[&id]).unwrap();
    assert!(
        row.is_some(),
        "actual agent must register its sealed stage, not only return attestation metadata"
    );
    let row = row.unwrap();
    assert_eq!(
        proto::RuntimeLaunchAttestation::decode(row.get::<_, Vec<u8>>(0).as_slice()).unwrap(),
        expected
    );
    let binding =
        proto::ManagedDeploymentBinding::decode(row.get::<_, Vec<u8>>(1).as_slice()).unwrap();
    let stage = f.root.join("staging").join(format!("apex-runtime-{id}"));
    let proof = zeroize::Zeroizing::new(std::fs::read(stage.join("instance-proof")).unwrap());
    assert_eq!(proof.len(), 32);
    assert_eq!(
        format!("{:x}", Sha256::digest(&*proof)),
        expected.instance_proof_sha256
    );
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(stage.join("authority-profile.json")).unwrap())
            .unwrap();
    assert_eq!(profile["schema_version"], 2);
    assert_eq!(profile["profile"]["mode"], "managed_preparation");
    runtime.block_on(async {
        let mut client =
            proto::managed_runtime_authority_client::ManagedRuntimeAuthorityClient::new(
                process::channel(&f, f.cp, pki::OTHER).await,
            );
        let mut request = tonic::Request::new(proto::ManagedDeploymentRenewal {
            binding: Some(binding.clone()),
            nonce: vec![8; 32],
            renewal_sequence: 1,
            applied: None,
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", configuration::WORKLOAD_TOKEN)
                .parse()
                .unwrap(),
        );
        request.metadata_mut().insert_bin(
            "apex-instance-proof-bin",
            tonic::metadata::MetadataValue::from_bytes(&proof),
        );
        let grant = client.renew_deployment(request).await.unwrap().into_inner();
        assert_eq!(grant.mode, proto::ManagedGrantMode::Prepare as i32);
        assert_eq!(grant.binding, Some(binding));
        assert!((1..=10_000_000).contains(&grant.valid_for_us));
    });
    drop(proof);
    cp.stop();
    agent.stop();
    drop(runtime);
    // Keep owned immutable stage/journal and dormant container as evidence;
    // this fixture does not manufacture a live gateway from the signed image.
}
