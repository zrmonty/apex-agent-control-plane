use super::*;

fn changed_target_refuses_work(change: &str, acquire_before_change: bool) {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let accepted = submit_operation(&mut tx, &submission(target, &revision, &event)).unwrap();
    let lease = acquire_before_change.then(|| {
        lease_operation(&mut tx, target, "worker", Duration::from_secs(30))
            .unwrap()
            .unwrap()
    });
    let intents = pending_evidence_intents(&mut tx, target, 10).unwrap();
    // Legacy lifecycle updates can change the authoritative target without a generation bump.
    tx.execute(change, &[]).unwrap();
    let current = tx
        .query_one(
            "SELECT desired_state, active_revision_id, deployment_generation, observed_status
         FROM mcp_proxies",
            &[],
        )
        .unwrap();
    assert_eq!(current.get::<_, i64>(2), 1);
    if let Some(lease) = lease {
        let mut observed_event = event.clone();
        observed_event.event_id = Uuid::now_v7().to_string();
        observed_event.integrity.as_mut().unwrap().event_hash =
            canonical_event_hash(&observed_event).unwrap();
        let error = observe_operation(
            &mut tx,
            target,
            &lease,
            ProxyObservedState::Ready,
            None,
            &observed_event,
        )
        .expect_err("the live proxy target must still match the durable operation");
        assert_eq!(error.code(), "PROXY_STALE_FENCE");
    } else {
        assert!(
            lease_operation(&mut tx, target, "worker", Duration::from_secs(30))
                .unwrap()
                .is_none(),
            "a superseded target must not be leased"
        );
        assert_eq!(
            tx.query_one("SELECT count(*) FROM mcp_proxy_controller_leases", &[])
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    assert_eq!(
        get_operation(&mut tx, target, &accepted.operation_id).unwrap(),
        Some(accepted)
    );
    assert_eq!(
        pending_evidence_intents(&mut tx, target, 10).unwrap(),
        intents
    );
    let after = tx
        .query_one(
            "SELECT desired_state, active_revision_id, deployment_generation, observed_status
         FROM mcp_proxies",
            &[],
        )
        .unwrap();
    assert_eq!(after.get::<_, String>(0), current.get::<_, String>(0));
    assert_eq!(
        after.get::<_, Option<Uuid>>(1),
        current.get::<_, Option<Uuid>>(1)
    );
    assert_eq!(after.get::<_, i64>(2), current.get::<_, i64>(2));
    assert_eq!(
        after.get::<_, Option<String>>(3),
        current.get::<_, Option<String>>(3)
    );
}

#[test]
fn lease_refuses_legacy_desired_state_change_without_generation_change() {
    changed_target_refuses_work("UPDATE mcp_proxies SET desired_state = 'paused'", false);
}

#[test]
fn observation_refuses_legacy_desired_state_change_without_generation_change() {
    changed_target_refuses_work("UPDATE mcp_proxies SET desired_state = 'paused'", true);
}

#[test]
fn lease_refuses_active_revision_change_without_generation_change() {
    for change in [
        "UPDATE mcp_proxies SET active_revision_id = '018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99'",
        "UPDATE mcp_proxies SET active_revision_id = NULL",
    ] {
        changed_target_refuses_work(change, false);
    }
}

#[test]
fn observation_refuses_active_revision_change_without_generation_change() {
    for change in [
        "UPDATE mcp_proxies SET active_revision_id = '018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99'",
        "UPDATE mcp_proxies SET active_revision_id = NULL",
    ] {
        changed_target_refuses_work(change, true);
    }
}
