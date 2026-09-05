use super::support::*;
use apex_control_plane_api::{PostgresProxyStore, proto};
use std::time::Duration;
use uuid::Uuid;

#[test]
fn published_current_operation_returns_database_checked_data_without_mutation() {
    let f = Fixture::new(true);
    assert_eq!(f.target.generation, 1);
    assert_eq!(f.target.fencing_token, 1);
    // Publication is not inferred from lifecycle: the real writer stamps Draft.
    assert_eq!(
        f.revision.lifecycle_state,
        apex_control_plane_api::ProxyLifecycleState::Draft
    );
    f.positive();
}

#[test]
fn a_published_operation_without_a_lease_is_not_current() {
    let f = Fixture::new(false);
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
}

#[test]
fn every_exact_target_operation_and_worker_claim_must_match_the_current_rows() {
    let f = Fixture::new(true);
    f.positive();
    for field in 0..5 {
        let mut target = f.target.clone();
        match field {
            0 => target.workspace_id = "other-workspace".into(),
            1 => target.namespace_id = "other-namespace".into(),
            2 => target.proxy_id = Uuid::now_v7().to_string(),
            3 => target.revision_id = Uuid::now_v7().to_string(),
            _ => target.generation += 1,
        }
        f.reject(&target, &f.operation.operation_id, "controller-a", REFUSED);
    }
    f.reject(
        &f.target,
        &Uuid::now_v7().to_string(),
        "controller-a",
        REFUSED,
    );
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-b",
        REFUSED,
    );
    f.positive();
}

#[test]
fn lower_greater_and_maximum_claimed_fences_never_advance_or_replace_the_live_fence() {
    let mut f = Fixture::new(true);
    f.expired_at_database_edge();
    f.lease = f
        .store
        .lease_proxy_operation(
            &f.input.scope,
            &f.input.proxy_id,
            "controller-a",
            Duration::from_secs(30),
        )
        .unwrap();
    f.target.fencing_token = 2;
    f.positive();
    for fence in [1, 3, u64::try_from(i64::MAX).unwrap()] {
        let target = proto::RuntimeTarget {
            fencing_token: fence,
            ..f.target.clone()
        };
        f.reject(&target, &f.operation.operation_id, "controller-a", REFUSED);
    }
    f.positive();
}

#[test]
fn exact_sql_maximum_fence_remains_readable_without_increment_or_numeric_rounding() {
    let mut f = Fixture::new(true);
    f.positive();
    f.execute(
        "UPDATE mcp_proxy_controller_leases SET fencing_token=$2 WHERE proxy_id=$1",
        &[f.input.proxy_id.as_uuid(), &i64::MAX],
    );
    f.target.fencing_token = u64::try_from(i64::MAX).unwrap();
    f.lease.as_mut().unwrap().fencing_token = f.target.fencing_token;
    f.positive();
}

#[test]
fn malformed_scope_uuid_worker_and_out_of_sql_range_numbers_fail_closed() {
    let f = Fixture::new(true);
    f.positive();
    for id in [
        "",
        "SNAPSHOT_CANARY",
        "018F3D4A-8B9C-7D0E-8F12-3A4B5C6D7E87",
        "018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e87",
        "018f3d4a-8b9c-7d0e-cf12-3a4b5c6d7e87",
    ] {
        for field in 0..3 {
            let mut target = f.target.clone();
            let mut operation = f.operation.operation_id.clone();
            match field {
                0 => target.proxy_id = id.into(),
                1 => target.revision_id = id.into(),
                _ => operation = id.into(),
            }
            f.reject(&target, &operation, "controller-a", INVALID);
        }
    }
    for scope in [String::new(), "a..b".into(), "a/b".into(), "a".repeat(257)] {
        for field in 0..2 {
            let mut target = f.target.clone();
            if field == 0 {
                target.workspace_id = scope.clone();
            } else {
                target.namespace_id = scope.clone();
            }
            f.reject(&target, &f.operation.operation_id, "controller-a", INVALID);
        }
    }
    for worker in [
        String::new(),
        "SNAPSHOT_CANARY\n".into(),
        "bad/worker".into(),
        "w".repeat(129),
    ] {
        f.reject(&f.target, &f.operation.operation_id, &worker, INVALID);
    }
    for value in [0, u64::try_from(i64::MAX).unwrap() + 1, u64::MAX] {
        for field in 0..2 {
            let mut target = f.target.clone();
            if field == 0 {
                target.generation = value;
            } else {
                target.fencing_token = value;
            }
            f.reject(&target, &f.operation.operation_id, "controller-a", INVALID);
        }
    }
    f.positive();
}

#[test]
fn reconnect_returns_persisted_current_data_not_a_cached_or_reissued_lease() {
    let f = Fixture::new(true);
    f.positive();
    let before = f.bytes();
    let store = PostgresProxyStore::connect(&f.database.url).unwrap();
    let snapshot = store
        .read_current_runtime_operation(&f.target, &f.operation.operation_id, "controller-a")
        .unwrap();
    assert_eq!(snapshot.operation, f.operation);
    assert_eq!(snapshot.revision, f.revision);
    assert_eq!(snapshot.fencing_token, 1);
    assert_eq!(
        snapshot.lease_expires_at_unix_us,
        f.lease.as_ref().unwrap().lease_expires_at_micros
    );
    assert_eq!(f.bytes(), before);
}
