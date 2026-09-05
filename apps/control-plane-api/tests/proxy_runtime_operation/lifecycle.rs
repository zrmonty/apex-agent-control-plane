use super::support::*;
use apex_control_plane_api::proto::{ProxyDesiredState as Desired, ProxyObservedState as Observed};
use uuid::Uuid;

#[test]
fn current_nonterminal_rows_remain_readable_for_each_durable_desired_state() {
    for desired in [Desired::Serving, Desired::Paused, Desired::Retired] {
        let mut f = Fixture::desired(true, desired);
        f.positive();
        for state in [
            Observed::Reconciling,
            Observed::Failed,
            Observed::NotServing,
        ] {
            f.operation = f
                .store
                .observe_proxy_operation(
                    &f.input.scope,
                    &f.input.proxy_id,
                    f.lease.as_ref().unwrap(),
                    state,
                    None,
                    &f.observation(),
                )
                .unwrap();
            f.positive();
        }
    }
}

#[test]
fn equal_fence_expires_at_a_database_sampled_edge_without_host_wall_arithmetic() {
    let f = Fixture::new(true);
    f.positive();
    let edge = f.expired_at_database_edge();
    assert!(database_now(&mut f.client()) >= edge);
    // Keep operation/worker/fence exact; only durable database expiry changes.
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
}

#[test]
fn legacy_active_revision_and_desired_state_changes_refuse_without_generation_bumps() {
    let f = Fixture::new(true);
    f.positive();
    for active in [None, Some(Uuid::now_v7())] {
        f.execute(
            "UPDATE mcp_proxies SET active_revision_id=$2 WHERE proxy_id=$1",
            &[f.input.proxy_id.as_uuid(), &active],
        );
        f.reject(
            &f.target,
            &f.operation.operation_id,
            "controller-a",
            REFUSED,
        );
    }
    f.execute(
        "UPDATE mcp_proxies SET active_revision_id=$2,desired_state='paused' WHERE proxy_id=$1",
        &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid()],
    );
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
    let generation: i64 = f
        .client()
        .query_one(
            "SELECT deployment_generation FROM mcp_proxies WHERE proxy_id=$1",
            &[f.input.proxy_id.as_uuid()],
        )
        .unwrap()
        .get(0);
    assert_eq!(generation, 1);
    f.execute(
        "UPDATE mcp_proxies SET desired_state='serving' WHERE proxy_id=$1",
        &[f.input.proxy_id.as_uuid()],
    );
    f.positive();
}

#[test]
fn completed_rows_refuse_snapshots_but_preserve_exact_event_and_acceptance_retries() {
    for (desired, terminal) in [
        (Desired::Serving, Observed::Ready),
        (Desired::Paused, Observed::Paused),
        (Desired::Retired, Observed::Retired),
    ] {
        let f = Fixture::desired(true, desired);
        f.positive();
        let lease = f.lease.as_ref().unwrap();
        let progress_event = f.observation();
        let progress = f
            .store
            .observe_proxy_operation(
                &f.input.scope,
                &f.input.proxy_id,
                lease,
                Observed::Reconciling,
                None,
                &progress_event,
            )
            .unwrap();
        let completed_event = f.observation();
        let completed = f
            .store
            .observe_proxy_operation(
                &f.input.scope,
                &f.input.proxy_id,
                lease,
                terminal,
                None,
                &completed_event,
            )
            .unwrap();
        f.reject(
            &f.target,
            &f.operation.operation_id,
            "controller-a",
            REFUSED,
        );
        let before = f.bytes();
        assert_eq!(
            f.store.submit_proxy_operation(&f.input).unwrap(),
            f.operation
        );
        assert_eq!(
            f.store
                .observe_proxy_operation(
                    &f.input.scope,
                    &f.input.proxy_id,
                    lease,
                    terminal,
                    None,
                    &completed_event,
                )
                .unwrap(),
            completed
        );
        assert_eq!(
            f.store
                .observe_proxy_operation(
                    &f.input.scope,
                    &f.input.proxy_id,
                    lease,
                    Observed::Reconciling,
                    None,
                    &progress_event,
                )
                .unwrap(),
            progress
        );
        assert_eq!(
            f.store
                .observe_proxy_operation(
                    &f.input.scope,
                    &f.input.proxy_id,
                    lease,
                    Observed::Failed,
                    None,
                    &f.observation(),
                )
                .unwrap_err()
                .code(),
            "INVALID_PROXY_LIFECYCLE_TRANSITION"
        );
        assert_eq!(f.bytes(), before);
    }
}
