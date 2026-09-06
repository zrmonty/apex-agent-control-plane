use super::*;

fn prepare(f: &Fixture) -> Uuid {
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let pre = f
        .store
        .renew_deployment_checked(&renewal(f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(f, 2, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    f.store
        .record_candidate_readiness_checked(
            &f.lease,
            &f.registration.binding,
            &ready(f),
            &|| Ok(()),
        )
        .unwrap()
}

#[test]
fn old_serve_new_prepare_selection_requires_exact_closed_drain() {
    let mut f = Fixture::new();
    let observed = prepare(&f);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observed, &|| Ok(()))
        .unwrap();
    let old = f.registration.clone();
    let serving = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    f.advance(proto::ProxyDesiredState::Serving, true);
    let candidate = prepare(&f);
    let mut old_request = renewal(&f, 4, Some(ack(&serving, true, 2)));
    old_request.binding = Some(old.binding.clone());
    let continued = f
        .store
        .renew_deployment_checked(&old_request, &|| Ok(()))
        .unwrap();
    assert_eq!(
        continued.mode, 2,
        "desired revision change must preserve eligible selected identity"
    );
    assert_ne!(
        old.binding.target.as_ref().unwrap().revision_id,
        f.registration.binding.target.as_ref().unwrap().revision_id
    );
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, candidate, &|| Ok(()))
            .is_err()
    );
    f.store
        .withdraw_deployment_checked(&f.lease, &old.binding, Withdrawal::Replacement, &|| Ok(()))
        .unwrap();
    old_request.renewal_sequence = 5;
    let closed = f
        .store
        .renew_deployment_checked(&old_request, &|| Ok(()))
        .unwrap();
    assert_eq!(closed.mode, 3);
    old_request.renewal_sequence = 6;
    old_request.applied = Some(ack(&closed, false, 1));
    let newer_closed = f
        .store
        .renew_deployment_checked(&old_request, &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, candidate, &|| Ok(()))
            .is_err()
    );
    old_request.renewal_sequence = 7;
    old_request.applied = Some(ack(&newer_closed, false, 0));
    f.store
        .renew_deployment_checked(&old_request, &|| Ok(()))
        .unwrap();
    let epoch = f
        .store
        .select_candidate_checked(&f.lease, &f.registration.binding, candidate, &|| Ok(()))
        .unwrap();
    let grant = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    assert_eq!(grant.mode, 2);
    assert_eq!(grant.epoch, epoch);
    let row = f
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_deployments WHERE mode=2",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
}

#[test]
fn lost_replies_pin_last_applied_and_pruned_sequences_refuse() {
    let f = Fixture::new();
    prepare(&f);
    let original = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    let last = ack(&original, false, 0);
    for sequence in 4..=75 {
        f.store
            .renew_deployment_checked(&renewal(&f, sequence, Some(last.clone())), &|| Ok(()))
            .unwrap();
    }
    assert_eq!(f.rows("mcp_proxy_grant_decisions").len(), 64);
    assert!(
        f.store
            .renew_deployment_checked(&renewal(&f, 4, Some(last.clone())), &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .renew_deployment_checked(&renewal(&f, 76, Some(last)), &|| Ok(()))
            .is_ok()
    );
    let mut unknown = ack(&original, false, 0);
    unknown.decision_id = Uuid::now_v7().to_string();
    assert!(
        f.store
            .renew_deployment_checked(&renewal(&f, 77, Some(unknown)), &|| Ok(()))
            .is_err()
    );
    let mut wrong_epoch = ack(&original, false, 0);
    wrong_epoch.epoch += 1;
    assert!(
        f.store
            .renew_deployment_checked(&renewal(&f, 77, Some(wrong_epoch)), &|| Ok(()))
            .is_err()
    );
}

#[test]
fn actual_grant_expiry_refuses_retry_without_erasing_physical_calls() {
    let f = Fixture::new();
    let observation = prepare(&f);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
        .unwrap();
    let serving = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    let request = renewal(&f, 4, Some(ack(&serving, true, 2)));
    f.store
        .renew_deployment_checked(&request, &|| Ok(()))
        .unwrap();
    // Actual DB time, no forged clock or mutation of immutable issued decisions.
    f.client().query_one("SELECT pg_sleep(10.01)", &[]).unwrap();
    assert!(
        f.store
            .renew_deployment_checked(&request, &|| Ok(()))
            .is_err()
    );
    assert_eq!(
        f.client()
            .query_one("SELECT active_calls FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        f.store
            .renew_deployment_checked(&renewal(&f, 5, None), &|| Ok(()))
            .unwrap()
            .mode,
        2
    );
    assert_eq!(
        f.client()
            .query_one("SELECT active_calls FROM mcp_proxy_deployments", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
}

#[test]
fn stale_ack_never_rewinds_physical_state_and_old_prepare_ack_cannot_prove_closure() {
    let f = Fixture::new();
    let observation = prepare(&f);
    let pre = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
        .unwrap();
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
        .unwrap();
    let serve = f
        .store
        .renew_deployment_checked(&renewal(&f, 4, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 5, Some(ack(&serve, true, 3))), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 6, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    let row = f
        .client()
        .query_one(
            "SELECT active_calls,admitting FROM mcp_proxy_deployments",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 3);
    assert!(row.get::<_, bool>(1));
}

#[test]
fn selected_renewal_does_not_require_nonterminal_operation_or_live_controller() {
    let f = Fixture::new();
    let observation = prepare(&f);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
        .unwrap();
    let mut terminal = f.lease.operation.clone();
    terminal.observed_state = proto::ProxyObservedState::Ready as i32;
    f.client()
        .execute(
            "UPDATE mcp_proxy_operations SET observed_state=3,current_result=$1",
            &[&terminal.encode_to_vec()],
        )
        .unwrap();
    f.client()
        .execute(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0",
            &[],
        )
        .unwrap();
    let restarted = PostgresProxyStore::connect(&f.url).unwrap();
    assert_eq!(
        restarted
            .renew_deployment_checked(&renewal(&f, 3, None), &|| Ok(()))
            .unwrap()
            .mode,
        2
    );
}

#[test]
fn pause_closes_old_and_candidate_and_resume_cannot_revive_same_identity() {
    let mut f = Fixture::new();
    let observation = prepare(&f);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
        .unwrap();
    let old = f.registration.clone();
    f.advance(proto::ProxyDesiredState::Serving, true);
    prepare(&f);
    let candidate = f.registration.clone();
    f.advance(proto::ProxyDesiredState::Paused, false);
    let epoch = f
        .store
        .withdraw_deployment_checked(&f.lease, &old.binding, Withdrawal::Pause, &|| Ok(()))
        .unwrap();
    assert!(epoch > 1);
    let mut request = renewal(&f, 5, None);
    request.binding = Some(candidate.binding.clone());
    assert_eq!(
        f.store
            .renew_deployment_checked(&request, &|| Ok(()))
            .unwrap()
            .mode,
        3
    );
    f.advance(proto::ProxyDesiredState::Serving, false);
    request.renewal_sequence = 6;
    assert_eq!(
        f.store
            .renew_deployment_checked(&request, &|| Ok(()))
            .unwrap()
            .mode,
        3
    );
    assert!(
        f.client()
            .query_one(
                "SELECT selected_instance IS NULL FROM mcp_proxy_serving_selection",
                &[]
            )
            .unwrap()
            .get::<_, bool>(0)
    );
}
