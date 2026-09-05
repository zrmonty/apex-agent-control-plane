//! Separately compiled production agent client -> actual production root -> PG.
use super::*;
use apex_control_plane_api::{
    ExactScope, RuntimeDeploymentBindings, SecretRef, compile_runtime_config, proto,
};

fn document(fixture: &Fixture, materials: &material::Materials) -> serde_json::Value {
    // Published operation fixture has one HTTP upstream; deploy-owned metadata.
    let mut golden: proto::RuntimeConfiguration = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    ))
    .unwrap();
    golden.tool_schemas[0].upstream_id = "portfolio".into();
    serde_json::json!({"schemaVersion":1,"version":"root-bindings-1",
        "validFromUnixUs":materials.peer["validFromUnixUs"],"expiresAtUnixUs":materials.peer["expiresAtUnixUs"],
        "profiles":[{"installationId":material::INSTALLATION,"workspaceId":fixture.target.workspace_id,
            "namespaceId":fixture.target.namespace_id,"proxyId":fixture.target.proxy_id,"revisionId":fixture.target.revision_id,
            "hostPolicyVersion":"live-host-policy-1","resourceUrl":"https://gateway.example.test/mcp",
            "images":[{"digest":fixture.revision.spec.runtime_profile.image_digest,
                "imageRef":format!("ghcr.io/apex/gateway@{}",fixture.revision.spec.runtime_profile.image_digest)}],
            "secretRefs":["secret://SNAPSHOT_CANARY/upstream"],"toolSchemas":golden.tool_schemas,
            "approvedOutputProfiles":["portfolio-read-v1"],
            "networkGrants":[{"grantId":"portfolio-public","host":"portfolio.example.test","port":443,"approvedCidrs":["8.8.8.8/32"]}],
            "auth":{"issuer":"https://identity.example.test/","audience":"https://gateway.example.test/mcp",
                "jwksUri":"https://identity.example.test/jwks","requiredScopes":["mcp:invoke"],"workloadIdentityRef":"identity://runtime/agent"},
            "telemetry":golden.telemetry,"pidLimit":64}]})
}

#[test]
fn agent_resolves_configuration_from_actual_production_root_and_published_revision() {
    let fixture = Fixture::new(true);
    settle_evidence(&fixture);
    let pki = pki::Pki::require();
    let materials = material::Materials::new(&fixture, &pki);
    let document = document(&fixture, &materials);
    let profile: proto::RuntimeDeploymentProfile =
        serde_json::from_value(document["profiles"][0].clone()).unwrap();
    let expected = compile_runtime_config(
        &fixture.revision,
        &RuntimeDeploymentBindings {
            scope: ExactScope {
                workspace_id: fixture.target.workspace_id.clone(),
                namespace_id: fixture.target.namespace_id.clone(),
            },
            generation: fixture.target.generation,
            resource_url: profile.resource_url,
            image_catalog: profile
                .images
                .into_iter()
                .map(|i| (i.digest, i.image_ref))
                .collect(),
            secret_refs: profile
                .secret_refs
                .iter()
                .map(|s| SecretRef::new(s).unwrap())
                .collect(),
            tool_schemas: profile.tool_schemas,
            approved_output_profiles: profile.approved_output_profiles.into_iter().collect(),
            network_grants: profile.network_grants,
            auth: profile.auth.unwrap(),
            telemetry: profile.telemetry.unwrap(),
            pid_limit: profile.pid_limit,
        },
    )
    .unwrap();
    let before = fixture.bytes();
    let root = root::Root::start_with_deployment(&fixture, &pki, &materials, Some(&document));
    let mut request = CheckRuntimeAuthorityRequest {
        schema_version: 1,
        target: Some(fixture.target.clone()),
        operation_id: fixture.operation.operation_id.clone(),
        command_id: uuid::Uuid::now_v7().to_string(),
        action: 1,
        installation_id: "caller-not-authority".into(),
        observed_controller_certificate_sha256: vec![0xff; 32],
    };
    let resolved = root.probe_mode(
        &materials,
        &request,
        &fixture.revision.config_hash,
        "controller",
        true,
    );
    assert_eq!(
        resolved["resolution"]["manifestHash"],
        expected.runtime_manifest_hash
    );
    assert_eq!(resolved["resolution"]["bindingsVersion"], "root-bindings-1");
    assert_eq!(resolved["resolution"]["resourceUrl"], expected.resource_url);
    assert_eq!(
        resolved["snapshot"]["configHash"],
        fixture.revision.config_hash
    );
    root::assert_refusal(
        root.probe_mode(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "agent",
            true,
        ),
        "RUNTIME_AUTHORITY_CLIENT_DENIED",
    );
    request.target.as_mut().unwrap().fencing_token += 1;
    root::assert_refusal(
        root.probe_mode(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "controller",
            true,
        ),
        "RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL",
    );
    request.target.as_mut().unwrap().fencing_token -= 1;
    assert_unchanged(fixture.bytes(), &before);
    fixture.expired_at_database_edge();
    root::assert_refusal(
        root.probe_mode(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "controller",
            true,
        ),
        "RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL",
    );
    root.finish();
}
