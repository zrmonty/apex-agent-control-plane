use super::*;
use serde_json::{Value, json};

pub(super) fn prepare(
    f: &fixture::Fixture,
    pki: &pki::Pki,
    base: &std::path::Path,
) -> proto::RegisterRuntimeDeploymentRequest {
    let b = &f.registration.binding;
    let t = b.target.as_ref().unwrap();
    let grant = json!({"installationId":b.installation_id,"workspaceId":t.workspace_id,"namespaceId":t.namespace_id});
    let peer = json!({"schemaVersion":1,"version":"policy-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807",
        "peers":[{"certificateSha256":pki::hex(&pki.pin(pki::AGENT)),"identityId":"agent-a","role":"agent","revoked":false,"grants":[grant.clone()]},
        {"certificateSha256":pki::hex(&pki.pin(pki::CONTROLLER)),"identityId":"controller-a","role":"controller","revoked":false,"grants":[grant]}]});
    let enrollment = json!({"schemaVersion":1,"version":"enrollment-1","peerPolicyVersion":"policy-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807",
        "controllers":[{"identityId":"controller-a","workerId":f.lease.worker_id}],
        "installations":[{"installationId":b.installation_id,"agentIdentityId":"agent-a","revoked":false,"hostPolicyVersion":"host-policy-1",
        "scopes":[{"workspaceId":t.workspace_id,"namespaceId":t.namespace_id}]}]});
    let c = serde_json::to_value(&f.registration.configuration).unwrap();
    let deployment = json!({"schemaVersion":1,"version":"deployment-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807",
        "profiles":[{"installationId":b.installation_id,"workspaceId":t.workspace_id,"namespaceId":t.namespace_id,"proxyId":t.proxy_id,"revisionId":t.revision_id,
        "hostPolicyVersion":"host-policy-1","resourceUrl":c["resourceUrl"],"images":[{"digest":c["spec"]["runtimeProfile"]["imageDigest"],"imageRef":c["imageRef"]}],
        "secretRefs":c["secretRefs"],"toolSchemas":c["toolSchemas"],"approvedOutputProfiles":["portfolio-read-v1"],"networkGrants":c["networkGrants"],
        "auth":c["auth"],"telemetry":c["telemetry"],"pidLimit":c["pidLimit"]}]});
    let materials: Vec<_> = (1..=13)
        .rev()
        .map(|role| proto::RuntimeMaterialBinding {
            role,
            reference: format!("secret://registration/material-{role}"),
            version: "v1".into(),
        })
        .collect();
    let expected_materials: Vec<_> = materials.iter().map(|m| json!({"role":proto::RuntimeMaterialRole::try_from(m.role).unwrap().as_str_name(),"reference":m.reference,"version":m.version})).collect();
    let image_id = format!("sha256:{}", "d".repeat(64));
    let managed = json!({"schema_version":1,"version":"v1","valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807",
        "profiles":[{"installation_id":b.installation_id,"workspace_id":t.workspace_id,"namespace_id":t.namespace_id,"proxy_id":t.proxy_id,"revision_id":t.revision_id,
        "authority_profile_ref":f.registration.authority_profile_ref,"authority_profile_version":f.registration.authority_profile_version,"evidence_agent_id":"managed-component-proxy",
        "credentials":[{"certificate_sha256":pki::hex(&pki.pin(pki::OTHER)),"token_sha256":format!("{:x}",Sha256::digest(b"managed-test-token-123"))}],
        "launch":{"config_hash":b.config_hash,"host_policy_version":"host-policy-1","deployment_bindings_version":"deployment-1","image_ref":c["imageRef"],"image_id":image_id,"materials":expected_materials}}]});
    for (name, value) in [
        ("peer.json", peer),
        ("enrollment.json", enrollment),
        ("deployment.json", deployment),
        ("managed.json", managed),
    ] {
        let path = base.join(name);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let health_ref = materials
        .iter()
        .find(|m| m.role == proto::RuntimeMaterialRole::HealthToken as i32)
        .unwrap()
        .reference
        .clone();
    let mut launch = proto::RuntimeLaunchContext {
        schema_version: 1,
        target: b.target.clone(),
        process_instance_id: b.process_instance_id.clone(),
        config_hash: b.config_hash.clone(),
        runtime_manifest_hash: f.registration.configuration.runtime_manifest_hash.clone(),
        image_ref: f.registration.configuration.image_ref.clone(),
        authority_profile_ref: f.registration.authority_profile_ref.clone(),
        authority_profile_version: f.registration.authority_profile_version.clone(),
        materials,
        health: Some(proto::RuntimeHealthBinding {
            port: 8081,
            credential_ref: health_ref,
        }),
        launch_context_hash: String::new(),
    };
    seal(&mut launch);
    proto::RegisterRuntimeDeploymentRequest {
        authority: Some(proto::CheckRuntimeAuthorityRequest {
            schema_version: 1,
            target: b.target.clone(),
            operation_id: f.lease.operation.operation_id.clone(),
            command_id: Uuid::now_v7().to_string(),
            action: proto::RuntimeAuthorityAction::CheckCurrentOperation as i32,
            installation_id: b.installation_id.clone(),
            observed_controller_certificate_sha256: pki.pin(pki::CONTROLLER).to_vec(),
        }),
        attestation: Some(proto::RuntimeLaunchAttestation {
            schema_version: 1,
            installation_id: b.installation_id.clone(),
            launch: Some(launch),
            instance_proof_sha256: pki::hex(&f.registration.proof_sha256),
            staged_manifest_sha256: "c".repeat(64),
            image_id,
        }),
    }
}

pub(super) fn seal(launch: &mut proto::RuntimeLaunchContext) {
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(fields) => {
                let mut fields: Vec<_> = fields.into_iter().collect();
                fields.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                Value::Object(fields.into_iter().map(|(k, v)| (k, sorted(v))).collect())
            }
            Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
            scalar => scalar,
        }
    }
    let mut value = serde_json::to_value(&*launch).unwrap();
    value.as_object_mut().unwrap().remove("launchContextHash");
    launch.launch_context_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&sorted(value)).unwrap())
    );
}

pub(super) async fn channel(
    pki: &pki::Pki,
    endpoint: &str,
    role: &str,
) -> tonic::transport::Channel {
    Endpoint::from_shared(endpoint.to_owned())
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("control-plane-api")
                .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
                .identity(pki.identity("trusted-host", role)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap()
}
