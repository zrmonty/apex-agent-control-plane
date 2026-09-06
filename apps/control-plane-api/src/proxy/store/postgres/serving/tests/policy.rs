use super::*;

#[test]
fn candidate_policy_read_is_eligible_read_only_and_pause_revokes_immediately() {
    let mut f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let binding = f.registration.binding.clone();
    let before = f.rows("mcp_proxy_deployments");
    let record = f
        .store
        .read_eligible_deployment_checked(&binding, &|| Ok(()))
        .unwrap();
    assert_eq!(record.mode, proto::ManagedGrantMode::Prepare);
    assert_eq!(before, f.rows("mcp_proxy_deployments"));
    assert!(f.rows("mcp_proxy_grant_decisions").is_empty());
    let revision = Uuid::parse_str(&binding.target.as_ref().unwrap().revision_id).unwrap();
    f.client()
        .execute(
            "UPDATE mcp_proxy_revisions SET is_published=false WHERE revision_id=$1",
            &[&revision],
        )
        .unwrap();
    assert!(
        f.store
            .read_eligible_deployment_checked(&binding, &|| Ok(()))
            .is_err()
    );
    f.client()
        .execute(
            "UPDATE mcp_proxy_revisions SET is_published=true WHERE revision_id=$1",
            &[&revision],
        )
        .unwrap();
    f.advance(proto::ProxyDesiredState::Paused, false);
    assert!(
        f.store
            .read_eligible_deployment_checked(&binding, &|| Ok(()))
            .is_err()
    );
    // Metadata remains readable for authenticated cleanup, not policy preflight.
    assert!(
        f.store
            .read_deployment_checked(&binding, &|| Ok(()))
            .is_ok()
    );
}

#[test]
fn closed_and_terminated_instances_have_no_policy_preflight_authority() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let binding = &f.registration.binding;
    let prepare = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&prepare, false, 0))), &|| Ok(()))
        .unwrap();
    let readiness = f
        .store
        .record_candidate_readiness_checked(&f.lease, binding, &ready(&f), &|| Ok(()))
        .unwrap();
    f.store
        .select_candidate_checked(&f.lease, binding, readiness, &|| Ok(()))
        .unwrap();
    f.store
        .withdraw_deployment_checked(&f.lease, binding, Withdrawal::Replacement, &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .read_eligible_deployment_checked(binding, &|| Ok(()))
            .is_err()
    );
    f.store
        .record_deployment_termination_checked(&f.lease, binding, &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .read_eligible_deployment_checked(binding, &|| Ok(()))
            .is_err()
    );
}
