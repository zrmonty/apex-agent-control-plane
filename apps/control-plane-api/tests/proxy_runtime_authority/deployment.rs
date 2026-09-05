//! Real PG publication + actual mTLS resolution. No container effects.
use crate::{
    callback,
    material::{INSTALLATION, Materials},
    operation::Fixture,
    pki::{self, Pki},
    transport,
};
use apex_control_plane_api::{proto, runtime_manifest_hash};
use serde_json::{Value, json};

pub(super) fn document(fixture: &Fixture, materials: &Materials) -> Value {
    json!({"schemaVersion":1,"version":"deployment-1",
    "validFromUnixUs":materials.peer["validFromUnixUs"],
    "expiresAtUnixUs":materials.peer["expiresAtUnixUs"],
    "profiles":[{
        "installationId":INSTALLATION,"workspaceId":fixture.target.workspace_id,
        "namespaceId":fixture.target.namespace_id,"proxyId":fixture.target.proxy_id,
        "revisionId":fixture.target.revision_id,"hostPolicyVersion":"live-host-policy-1",
        "resourceUrl":"https://gateway.example.test/mcp",
        "images":[{"digest":format!("sha256:{}", "a".repeat(64)),
            "imageRef":format!("ghcr.io/apex/gateway@sha256:{}", "a".repeat(64))}],
        "secretRefs":["secret://SNAPSHOT_CANARY/upstream"],
        "toolSchemas":[{"upstreamId":"portfolio","toolName":"portfolio.read",
            "inputSchemaJson":"{\"type\":\"object\"}","outputSchemaJson":"{\"type\":\"object\"}",
            "outputProfileId":"safe-output","schemaHash":"b".repeat(64)}],
        "approvedOutputProfiles":["safe-output"],
        "networkGrants":[{"grantId":"portfolio-public","host":"portfolio.example.test",
            "port":443,"approvedCidrs":["8.8.8.8/32"]}],
        "auth":{"issuer":"https://identity.example.test/","audience":"https://gateway.example.test/mcp",
            "jwksUri":"https://identity.example.test/jwks","requiredScopes":["mcp:invoke"],
            "workloadIdentityRef":"identity://runtime/agent"},
        "telemetry":{"fullTraceSamplePerMillion":1000000,"maxStages":32,"maxSummaryBytes":4096,
            "maxSpans":128,"maxAttributesPerSpan":32,"maxExportQueueBytes":"1048576"},
        "pidLimit":64
    }]})
}

#[test]
fn invalid_deployment_limits_fail_actual_owner_startup() {
    let fixture = Fixture::new(true);
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    for field in ["telemetry", "pidLimit"] {
        let mut invalid = document(&fixture, &materials);
        invalid["profiles"][0][field] = if field == "telemetry" {
            json!({})
        } else {
            json!(0)
        };
        let mut owner = materials.owner_with_deployment(&fixture.database.url, Some(&invalid));
        assert_eq!(
            owner.start().unwrap_err().code(),
            "RUNTIME_AUTHORITY_UNAVAILABLE"
        );
        assert!(owner.shutdown().cleanup_complete);
    }
}

#[test]
fn deployment_resolution_uses_published_pg_revision_and_exact_installation() {
    let fixture = Fixture::new(true);
    let before = fixture.bytes();
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let bindings = document(&fixture, &materials);
    let mut owner = materials.owner_with_deployment(&fixture.database.url, Some(&bindings));
    let service = owner.start().unwrap();
    let query = callback::request(&fixture, &pki);
    let expected = fixture.revision.clone();
    transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let channel = transport::channel(&pki, &endpoint, pki::AGENT).await;
        let mut client =
            proto::runtime_deployment_service_client::RuntimeDeploymentServiceClient::new(channel)
                .max_encoding_message_size(4096)
                .max_decoding_message_size(270_336);
        let reply = transport::within(client.resolve_runtime_deployment(query.clone()))
            .await
            .expect("published revision resolves through real mTLS/PG")
            .into_inner();
        assert_eq!(reply.deployment_bindings_version, "deployment-1");
        let authority = reply.authority.unwrap();
        assert_eq!(authority.target, query.target);
        assert_eq!(authority.operation_id, query.operation_id);
        let config = reply.configuration.unwrap();
        assert_eq!(config.config_hash, expected.config_hash);
        assert_eq!(config.revision_id, expected.revision_id.to_string());
        assert_eq!(
            config.runtime_manifest_hash,
            runtime_manifest_hash(&config).unwrap()
        );
        assert_eq!(config.resource_url, "https://gateway.example.test/mcp");
        assert_eq!(
            config.spec.unwrap().upstreams[0].endpoint_or_command_ref,
            "https://portfolio.example.test/mcp"
        );
        for case in 0..5 {
            let mut wrong = query.clone();
            match case {
                0 => wrong.installation_id = uuid::Uuid::now_v7().to_string(),
                1 => wrong.target.as_mut().unwrap().generation += 1,
                2 => wrong.target.as_mut().unwrap().fencing_token += 1,
                3 => wrong.target.as_mut().unwrap().revision_id = uuid::Uuid::now_v7().to_string(),
                _ => wrong.operation_id = uuid::Uuid::now_v7().to_string(),
            }
            let error = transport::within(client.resolve_runtime_deployment(wrong))
                .await
                .unwrap_err();
            assert!(matches!(
                error.code(),
                tonic::Code::PermissionDenied | tonic::Code::FailedPrecondition
            ));
            assert!(!error.to_string().contains("SNAPSHOT_CANARY"));
            assert!(error.details().is_empty());
        }
    });
    assert!(owner.shutdown().cleanup_complete);
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn deployment_file_rotation_and_missing_source_fail_closed_on_existing_channel() {
    use std::time::{Duration, Instant};
    let fixture = Fixture::new(true);
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let mut document = document(&fixture, &materials);
    let path = materials
        .enrollment_path()
        .with_file_name("deployment.json");
    let mut owner = materials.owner_with_deployment(&fixture.database.url, Some(&document));
    let service = owner.start().unwrap();
    let query = callback::request(&fixture, &pki);
    transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let channel = transport::channel(&pki, &endpoint, pki::AGENT).await;
        let mut client =
            proto::runtime_deployment_service_client::RuntimeDeploymentServiceClient::new(channel);
        transport::within(client.resolve_runtime_deployment(query.clone()))
            .await
            .unwrap();
        // Same version with different bytes must never silently change the manifest.
        document["profiles"][0]["pidLimit"] = 128.into();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            if let Err(error) =
                transport::within(client.resolve_runtime_deployment(query.clone())).await
            {
                assert!(matches!(
                    error.code(),
                    tonic::Code::Unavailable | tonic::Code::FailedPrecondition
                ));
                break;
            }
            assert!(Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        document["version"] = "deployment-2".into();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            if let Ok(reply) =
                transport::within(client.resolve_runtime_deployment(query.clone())).await
                && reply.get_ref().deployment_bindings_version == "deployment-2"
            {
                assert_eq!(
                    reply.get_ref().configuration.as_ref().unwrap().pid_limit,
                    128
                );
                break;
            }
            assert!(Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        std::fs::remove_file(&path).unwrap();
        // Outlive cached metadata, then require sustained refusal (not one try-lock race).
        tokio::time::sleep(Duration::from_millis(2200)).await;
        for _ in 0..3 {
            let error = transport::within(client.resolve_runtime_deployment(query.clone()))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable);
            assert_eq!(error.message(), "RUNTIME_AUTHORITY_UNAVAILABLE");
        }
    });
    assert!(owner.shutdown().cleanup_complete);
}
