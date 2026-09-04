use super::*;

fn observation_event() -> evidence::EventEnvelope {
    let mut event = envelope();
    event.event_id = Uuid::now_v7().to_string();
    event.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&event).unwrap();
    event
}

fn completed_command_rejects_new_events(desired: ProxyDesiredState, completed: ProxyObservedState) {
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
    let mut input = submission(target, &revision, &event);
    input.desired_state = desired;
    let accepted = submit_operation(&mut tx, &input).unwrap();
    let lease = lease_operation(&mut tx, target, "worker", Duration::from_secs(30))
        .unwrap()
        .unwrap();
    let progress_event = observation_event();
    let progress = observe_operation(
        &mut tx,
        target,
        &lease,
        ProxyObservedState::Reconciling,
        None,
        &progress_event,
    )
    .unwrap();
    let completed_event = observation_event();
    let result =
        observe_operation(&mut tx, target, &lease, completed, None, &completed_event).unwrap();
    let intents = pending_evidence_intents(&mut tx, target, 10).unwrap();
    assert_eq!(intents.len(), 3);

    // Both completion and earlier progress retries return their frozen response.
    assert_eq!(
        observe_operation(&mut tx, target, &lease, completed, None, &completed_event,).unwrap(),
        result
    );
    assert_eq!(
        observe_operation(
            &mut tx,
            target,
            &lease,
            ProxyObservedState::Reconciling,
            None,
            &progress_event,
        )
        .unwrap(),
        progress
    );
    for state in [
        ProxyObservedState::Reconciling,
        ProxyObservedState::Failed,
        ProxyObservedState::NotServing,
        completed,
    ] {
        let delayed = observation_event();
        let error = observe_operation(&mut tx, target, &lease, state, None, &delayed)
            .expect_err("a new event must not change a completed command");
        assert_eq!(error.code(), "INVALID_PROXY_LIFECYCLE_TRANSITION");
        assert_eq!(
            get_operation(&mut tx, target, &accepted.operation_id).unwrap(),
            Some(result.clone())
        );
        assert_eq!(
            pending_evidence_intents(&mut tx, target, 10).unwrap(),
            intents
        );
    }
    tx.execute(
        "UPDATE mcp_proxy_controller_leases SET expires_at_micros = 0",
        &[],
    )
    .unwrap();
    assert!(
        lease_operation(&mut tx, target, "next_worker", Duration::from_secs(30))
            .unwrap()
            .is_none()
    );
}

#[test]
fn ready_command_replays_exact_events_but_rejects_new_observations() {
    completed_command_rejects_new_events(ProxyDesiredState::Serving, ProxyObservedState::Ready);
}

#[test]
fn paused_command_replays_exact_events_but_rejects_new_observations() {
    completed_command_rejects_new_events(ProxyDesiredState::Paused, ProxyObservedState::Paused);
}

#[test]
fn retired_command_replays_exact_events_but_rejects_new_observations() {
    completed_command_rejects_new_events(ProxyDesiredState::Retired, ProxyObservedState::Retired);
}

#[test]
fn sql_guard_preserves_completed_command_state_result_and_timestamp() {
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
    for (desired, completed) in [
        (ProxyDesiredState::Serving, ProxyObservedState::Ready),
        (ProxyDesiredState::Paused, ProxyObservedState::Paused),
        (ProxyDesiredState::Retired, ProxyObservedState::Retired),
    ] {
        let mut case = tx.transaction().unwrap();
        let mut input = submission(target, &revision, &event);
        input.desired_state = desired;
        let accepted = submit_operation(&mut case, &input).unwrap();
        let lease = lease_operation(&mut case, target, "worker", Duration::from_secs(30))
            .unwrap()
            .unwrap();
        let result = observe_operation(
            &mut case,
            target,
            &lease,
            completed,
            None,
            &observation_event(),
        )
        .unwrap();
        for sql in [
            "UPDATE mcp_proxy_operations SET observed_state = 1",
            "UPDATE mcp_proxy_operations SET observed_state = 2",
            "UPDATE mcp_proxy_operations SET observed_state = 6",
            "UPDATE mcp_proxy_operations SET observed_state = 7",
            "UPDATE mcp_proxy_operations SET current_result = accepted_result",
            "UPDATE mcp_proxy_operations SET observed_at_micros = observed_at_micros + 1",
        ] {
            let mut tamper = case.transaction().unwrap();
            let error = tamper
                .execute(sql, &[])
                .expect_err("SQL must preserve a completed command");
            assert_eq!(
                error.code(),
                Some(&postgres::error::SqlState::CHECK_VIOLATION)
            );
            tamper.rollback().unwrap();
        }
        case.execute(
            "UPDATE mcp_proxy_operations SET current_result = current_result",
            &[],
        )
        .unwrap();
        assert_eq!(
            get_operation(&mut case, target, &accepted.operation_id).unwrap(),
            Some(result)
        );
        case.rollback().unwrap();
    }
}
