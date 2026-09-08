use super::*;
use uuid::Uuid;

mod fixture;
use fixture::Fixture;
mod attested;
mod boundaries;
mod concurrency;
mod health_consumption;
mod ordering;
mod policy;
mod readiness_progress;
mod schema;

fn renewal(
    f: &Fixture,
    sequence: u64,
    applied: Option<proto::ManagedGrantAcknowledgement>,
) -> proto::ManagedDeploymentRenewal {
    proto::ManagedDeploymentRenewal {
        binding: Some(f.registration.binding.clone()),
        nonce: vec![u8::try_from(sequence % 256).unwrap(); 32],
        applied,
        renewal_sequence: sequence,
    }
}
fn ack(
    g: &proto::ManagedDeploymentGrant,
    admitting: bool,
    active_calls: u32,
) -> proto::ManagedGrantAcknowledgement {
    proto::ManagedGrantAcknowledgement {
        decision_id: g.decision_id.clone(),
        epoch: g.epoch,
        admitting,
        active_calls,
    }
}
fn ready(f: &Fixture) -> CandidateReadiness {
    CandidateReadiness {
        expires: std::time::Instant::now() + std::time::Duration::from_secs(5),
        admitting: false,
        active_calls: 0,
        report: proto::ReadinessReport {
            live: true,
            ready: true,
            target: f.registration.binding.target.clone(),
            observed_at_unix_us: 1_788_500_000_000_000,
            config_hash: f.registration.binding.config_hash.clone(),
            runtime_manifest_hash: f.registration.configuration.runtime_manifest_hash.clone(),
            process_instance_id: f.registration.binding.process_instance_id.clone(),
            checks: (1..=9)
                .map(|id| proto::ReadinessCheck {
                    id,
                    status: 2,
                    reason: 1,
                })
                .collect(),
            stages: vec![],
            launch_context_hash: f.registration.binding.launch_context_hash.clone(),
        },
    }
}

#[test]
fn renewal_retry_preserves_decision_and_remaining_validity_without_terminal_lease() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let request = renewal(&f, 1, None);
    let g = f
        .store
        .renew_deployment_checked(&request, &|| Ok(()))
        .unwrap();
    assert_eq!(g.mode, 1);
    assert_eq!(g.epoch, 1);
    assert_eq!(g.renewal_sequence, 1);
    assert_eq!(g.nonce, request.nonce);
    assert!(g.valid_for_us > 0 && g.valid_for_us <= 10_000_000);
    let retry = f
        .store
        .renew_deployment_checked(&request, &|| Ok(()))
        .unwrap();
    assert_eq!(retry.decision_id, g.decision_id);
    assert!(retry.valid_for_us <= g.valid_for_us);
    let mut changed = request.clone();
    changed.applied = Some(ack(&g, false, 0));
    assert!(
        f.store
            .renew_deployment_checked(&changed, &|| Ok(()))
            .is_err()
    );
    let next = f
        .store
        .renew_deployment_checked(&renewal(&f, 4, Some(ack(&g, false, 0))), &|| Ok(()))
        .unwrap();
    assert_ne!(next.decision_id, g.decision_id);
    assert_eq!(next.renewal_sequence, 4);
}

#[test]
fn ready_selection_closure_and_exact_termination_are_explicit_transitions() {
    let f = Fixture::new();
    let b = &f.registration.binding;
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let pre = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    let observation = f
        .store
        .record_candidate_readiness_checked(&f.lease, b, &ready(&f), &|| Ok(()))
        .unwrap();
    let epoch = f
        .store
        .select_candidate_checked(&f.lease, b, observation, &|| Ok(()))
        .unwrap();
    assert!(epoch > pre.epoch);
    let serve = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    assert_eq!(serve.mode, 2);
    f.store
        .renew_deployment_checked(&renewal(&f, 4, Some(ack(&serve, true, 2))), &|| Ok(()))
        .unwrap();
    let closed_epoch = f
        .store
        .withdraw_deployment_checked(&f.lease, b, Withdrawal::Replacement, &|| Ok(()))
        .unwrap();
    assert!(closed_epoch > epoch);
    let closed = f
        .store
        .renew_deployment_checked(&renewal(&f, 5, Some(ack(&serve, true, 2))), &|| Ok(()))
        .unwrap();
    assert_eq!(closed.mode, 3);
    assert_eq!(
        f.client()
            .query_one("SELECT active_calls FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert!(
        f.store
            .select_candidate_checked(&f.lease, b, observation, &|| Ok(()))
            .is_err()
    );
    f.store
        .record_deployment_termination_checked(&f.lease, b, &|| Ok(()))
        .unwrap();
    let row = f
        .client()
        .query_one(
            "SELECT terminated,active_calls FROM mcp_proxy_deployments",
            &[],
        )
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, i64>(1), 0);
}

#[test]
fn registration_is_durable_exact_retry_and_conflicting_proof_refuses() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let before = f.rows("mcp_proxy_deployments");
    let restarted = PostgresProxyStore::connect(&f.url).unwrap();
    restarted
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    assert_eq!(before, f.rows("mcp_proxy_deployments"));
    let mut changed = f.registration.clone();
    changed.proof_sha256 = [9; 32];
    assert!(
        restarted
            .register_deployment_checked(&f.lease, &changed, &|| Ok(()))
            .is_err()
    );
    assert_eq!(before, f.rows("mcp_proxy_deployments"));
    assert_eq!(
        f.client()
            .query_one("SELECT mode FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, i32>(0),
        1
    );
}

#[test]
fn registered_metadata_is_readable_only_for_exact_binding_and_retains_applied_evidence() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let pre = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    let read = f
        .store
        .read_deployment_checked(&f.registration.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(read.registration.proof_sha256, [7; 32]);
    assert_eq!(
        read.registration.configuration,
        f.registration.configuration
    );
    assert_eq!(read.epoch, 1);
    assert_eq!(read.highest_sequence, 2);
    assert_eq!(read.mode, proto::ManagedGrantMode::Prepare);
    assert_eq!(
        read.applied.unwrap().decision_id.to_string(),
        pre.decision_id
    );
    let mut foreign = f.registration.binding.clone();
    foreign.installation_id = Uuid::now_v7().to_string();
    assert!(
        f.store
            .read_deployment_checked(&foreign, &|| Ok(()))
            .is_err()
    );
}
