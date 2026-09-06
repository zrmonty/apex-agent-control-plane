use super::*;
use crate::proxy::store::CandidateReadiness;
use tonic::transport::Channel;

fn signed<T>(input: T, binding: &proto::ManagedDeploymentBinding) -> Request<T> {
    let (metadata, _, _) = request(binding, 1).into_parts();
    Request::from_parts(metadata, tonic::Extensions::new(), input)
}

pub(super) async fn exercise(
    authority: &mut proto::managed_runtime_authority_client::ManagedRuntimeAuthorityClient<Channel>,
    governance: &mut proto::managed_proxy_governance_client::ManagedProxyGovernanceClient<Channel>,
    f: &fixture::Fixture,
    binding: &proto::ManagedDeploymentBinding,
    prepare: &proto::ManagedDeploymentGrant,
) {
    let target = binding.target.as_ref().unwrap();
    let input = proto::ManagedCallAuthorizationRequest {
        caller: Some(proto::GovernanceCaller {
            principal: "verified-subject".into(),
            agent_id: "managed-component-proxy".into(),
        }),
        scope: Some(proto::GovernanceScope {
            workspace_id: target.workspace_id.clone(),
            namespace_id: target.namespace_id.clone(),
        }),
        proxy_id: target.proxy_id.clone(),
        revision_id: target.revision_id.clone(),
        generation: target.generation,
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
        binding: Some(binding.clone()),
    };
    assert!(
        governance
            .authorize_managed_call(signed(input.clone(), binding))
            .await
            .is_err(),
        "PREPARE cannot reserve business work"
    );
    let mut ack = request(binding, 2);
    ack.get_mut().applied = Some(proto::ManagedGrantAcknowledgement {
        decision_id: prepare.decision_id.clone(),
        epoch: prepare.epoch,
        admitting: false,
        active_calls: 0,
    });
    authority.renew_deployment(ack).await.unwrap();
    tokio::task::block_in_place(|| {
        let ready = CandidateReadiness {
            admitting: false,
            active_calls: 0,
            report: proto::ReadinessReport {
                live: true,
                ready: true,
                target: binding.target.clone(),
                observed_at_unix_us: unix_us().unwrap(),
                config_hash: binding.config_hash.clone(),
                runtime_manifest_hash: f.registration.configuration.runtime_manifest_hash.clone(),
                process_instance_id: binding.process_instance_id.clone(),
                launch_context_hash: binding.launch_context_hash.clone(),
                checks: (1..=9)
                    .map(|id| proto::ReadinessCheck {
                        id,
                        status: 2,
                        reason: 1,
                    })
                    .collect(),
                stages: vec![],
            },
        };
        let id = f
            .store
            .record_candidate_readiness_checked(&f.lease, binding, &ready, &|| Ok(()))
            .unwrap();
        f.store
            .select_candidate_checked(&f.lease, binding, id, &|| Ok(()))
            .unwrap();
    });
    let serve = authority
        .renew_deployment(request(binding, 3))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(serve.mode, proto::ManagedGrantMode::Serve as i32);
    assert!(
        governance
            .authorize_managed_call(signed(input.clone(), binding))
            .await
            .is_err(),
        "unapplied SERVE is not admission"
    );
    let mut ack = request(binding, 4);
    ack.get_mut().applied = Some(proto::ManagedGrantAcknowledgement {
        decision_id: serve.decision_id.clone(),
        epoch: serve.epoch,
        admitting: true,
        active_calls: 0,
    });
    authority.renew_deployment(ack).await.unwrap();
    let permit = governance
        .authorize_managed_call(signed(input.clone(), binding))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        permit.decision.as_ref().unwrap().outcome,
        proto::GovernanceOutcome::Allowed as i32
    );
    assert_eq!(permit.policy_revision, 9_007_199_254_740_993);
    assert_eq!(permit.epoch, serve.epoch);
    assert!((1..=10_000_000).contains(&permit.valid_for_us));
    assert!(apex_domain::is_lowercase_uuidv7(&permit.admission_id));
    let retry = governance
        .authorize_managed_call(signed(input.clone(), binding))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(permit.admission_id, retry.admission_id);
    assert!(retry.valid_for_us <= permit.valid_for_us);
    let mut changed = input.clone();
    changed.arguments_hash = "c".repeat(64);
    assert!(
        governance
            .authorize_managed_call(signed(changed, binding))
            .await
            .is_err()
    );
    let completion = proto::ManagedCallCompletion {
        binding: Some(binding.clone()),
        admission_id: permit.admission_id,
        call_id: input.call_id.clone(),
    };
    for _ in 0..2 {
        let receipt = authority
            .complete_managed_call(signed(completion.clone(), binding))
            .await
            .unwrap()
            .into_inner();
        assert!(receipt.released);
        assert_eq!(receipt.binding, Some(binding.clone()));
        assert_eq!(receipt.call_id, input.call_id);
        assert_eq!(receipt.admission_id, completion.admission_id);
    }
    assert!(
        governance
            .authorize_managed_call(signed(input, binding))
            .await
            .is_err(),
        "released call never remints start authority"
    );
}
