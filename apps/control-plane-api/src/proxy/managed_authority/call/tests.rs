use super::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn fixture() -> (
    proto::RuntimeConfiguration,
    proto::ManagedCallAuthorizationRequest,
    GovernanceConfig,
) {
    let config: proto::RuntimeConfiguration = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    )))
    .unwrap();
    let policy = GovernanceConfig::new(
        ["northstar-401k"],
        [format!("{}/{}", config.workspace_id, config.namespace_id)],
        "ria-read-v1",
        9_007_199_254_740_993,
        ["client.tax_id"],
    )
    .unwrap();
    let input = proto::ManagedCallAuthorizationRequest {
        binding: Some(proto::ManagedDeploymentBinding {
            installation_id: Uuid::now_v7().to_string(),
            target: Some(proto::RuntimeTarget {
                workspace_id: config.workspace_id.clone(),
                namespace_id: config.namespace_id.clone(),
                proxy_id: config.proxy_id.clone(),
                revision_id: config.revision_id.clone(),
                generation: config.generation,
                fencing_token: 1,
            }),
            process_instance_id: Uuid::now_v7().to_string(),
            config_hash: config.config_hash.clone(),
            launch_context_hash: "b".repeat(64),
        }),
        caller: Some(proto::GovernanceCaller {
            principal: "verified-subject".into(),
            agent_id: "fixed-proxy-evidence".into(),
        }),
        scope: Some(proto::GovernanceScope {
            workspace_id: config.workspace_id.clone(),
            namespace_id: config.namespace_id.clone(),
        }),
        proxy_id: config.proxy_id.clone(),
        revision_id: config.revision_id.clone(),
        generation: config.generation,
        call_id: Uuid::now_v7().to_string(),
        tool_alias: "portfolio.read".into(),
        action: "read".into(),
        resource: format!("portfolio:sha256:{:x}", Sha256::digest(b"northstar-401k")),
        classification: "confidential".into(),
        arguments_hash: "a".repeat(64),
        trace: Some(proto::GovernanceTrace {
            trace_id: Uuid::now_v7().to_string(),
            span_id: "0123456789abcdef".into(),
        }),
        approval_id: String::new(),
    };
    (config, input, policy)
}

#[test]
fn actual_bound_policy_preserves_revision_restrictions_and_semantic_identity() {
    let (config, input, policy) = fixture();
    let result = evaluate(&input, &config, "fixed-proxy-evidence", &policy).unwrap();
    assert_eq!(
        result.decision.outcome,
        proto::GovernanceOutcome::Allowed as i32
    );
    assert_eq!(result.policy_revision, 9_007_199_254_740_993);
    assert_eq!(result.decision.field_restrictions, ["client.tax_id"]);
    assert_eq!(
        result.semantic_sha256,
        evaluate(&input, &config, "fixed-proxy-evidence", &policy)
            .unwrap()
            .semantic_sha256
    );
    let mut changed = input.clone();
    changed.arguments_hash = "c".repeat(64);
    assert_ne!(
        result.semantic_sha256,
        evaluate(&changed, &config, "fixed-proxy-evidence", &policy)
            .unwrap()
            .semantic_sha256
    );
    changed.resource = format!("portfolio:sha256:{:x}", Sha256::digest(b"foreign"));
    let denied = evaluate(&changed, &config, "fixed-proxy-evidence", &policy).unwrap();
    assert_eq!(
        denied.decision.outcome,
        proto::GovernanceOutcome::Denied as i32
    );
    assert!(denied.decision.field_restrictions.is_empty());
}

#[test]
fn body_claims_cannot_override_registered_mapping_or_enrolled_evidence_actor() {
    let (config, input, policy) = fixture();
    for bad in 0..12 {
        let mut changed = input.clone();
        match bad {
            0 => changed.caller.as_mut().unwrap().agent_id = "foreign-evidence".into(),
            1 => changed.scope.as_mut().unwrap().workspace_id = "foreign".into(),
            2 => changed.proxy_id = Uuid::now_v7().to_string(),
            3 => changed.revision_id = Uuid::now_v7().to_string(),
            4 => changed.generation += 1,
            5 => changed.tool_alias = "system.exec".into(),
            6 => changed.action = "execute".into(),
            7 => changed.classification = "public".into(),
            8 => changed.arguments_hash = "A".repeat(64),
            9 => changed.approval_id = Uuid::now_v7().to_string(),
            10 => changed.call_id = "bad".into(),
            11 => changed.binding.as_mut().unwrap().config_hash = "f".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            evaluate(&changed, &config, "fixed-proxy-evidence", &policy).is_err(),
            "bad {bad}"
        );
    }
    for bad in 0..4 {
        let mut changed = config.clone();
        let spec = changed.spec.as_mut().unwrap();
        match bad {
            0 => spec.governance_binding.as_mut().unwrap().policy_id = "foreign-policy".into(),
            1 => spec.governance_binding.as_mut().unwrap().approval_mode = "required".into(),
            2 => spec.exposed_tools[0].tool_name = "system.exec".into(),
            3 => spec.upstreams[0].transport = proto::McpProxyTransport::Stdio as i32,
            _ => unreachable!(),
        }
        assert!(
            evaluate(&input, &changed, "fixed-proxy-evidence", &policy).is_err(),
            "config {bad}"
        );
    }
}
