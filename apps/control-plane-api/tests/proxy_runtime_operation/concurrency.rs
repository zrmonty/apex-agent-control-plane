use super::support::*;
use apex_control_plane_api::{PostgresProxyStore, proto};
use std::sync::Barrier;
use std::time::{Duration, Instant};

fn pid(f: &Fixture) -> i32 {
    let rows = f.client().query(
        "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database()",
        &[&f.application],
    ).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "only the uniquely named test-owned connection is inspected"
    );
    rows[0].get(0)
}

fn wait_for_lock(f: &Fixture, pid: i32, fragment: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut client = f.client();
    while Instant::now() < deadline {
        let blocked: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1
             AND cardinality(pg_blocking_pids(pid))>0 AND position($2 in query)>0)",
                &[&pid, &fragment],
            )
            .unwrap()
            .get(0);
        if blocked {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn contended_proxy_lock_returns_bounded_safe_dependency_failure_and_recovers_without_mutation() {
    let f = Fixture::new(true);
    f.positive();
    let before = f.bytes();
    let mut blocker = f.client();
    let mut lock = blocker.transaction().unwrap();
    lock.query_one(
        "SELECT proxy_id FROM mcp_proxies WHERE proxy_id=$1 FOR UPDATE",
        &[f.input.proxy_id.as_uuid()],
    )
    .unwrap();
    let start = Instant::now();
    let result = f.read();
    let elapsed = start.elapsed();
    lock.rollback().unwrap();
    refused(result, UNAVAILABLE);
    assert!(
        elapsed < Duration::from_secs(7),
        "lock timeout must return, not pass by hanging"
    );
    assert_eq!(f.bytes(), before);
    f.positive();
}

#[test]
fn busy_store_refuses_without_mutex_wait_but_invalid_claims_are_checked_before_resource_access() {
    let f = Fixture::new(true);
    f.positive();
    let pid = pid(&f);
    let mut blocker = f.client();
    let mut lock = blocker.transaction().unwrap();
    lock.query_one(
        "SELECT proxy_id FROM mcp_proxies WHERE proxy_id=$1 FOR UPDATE",
        &[f.input.proxy_id.as_uuid()],
    )
    .unwrap();
    std::thread::scope(|scope| {
        let lookup = scope.spawn(|| f.read());
        let blocked = wait_for_lock(&f, pid, "FROM mcp_proxies");
        let start = Instant::now();
        let invalid = proto::RuntimeTarget {
            generation: u64::MAX,
            ..f.target.clone()
        };
        let rejected = f.store.read_current_runtime_operation(
            &invalid,
            &f.operation.operation_id,
            "controller-a",
        );
        let busy = f.read();
        let elapsed = start.elapsed();
        lock.rollback().unwrap();
        let completed = lookup.join().unwrap();
        assert!(
            blocked,
            "lookup must own the connection and reach the real row lock"
        );
        refused(rejected, INVALID);
        refused(busy, UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(1),
            "no waiting behind the busy store connection"
        );
        assert_eq!(completed.unwrap().operation, f.operation);
    });
    f.positive();
}

#[test]
fn lease_expiring_during_the_actual_revision_read_is_rechecked_before_commit() {
    let f = Fixture::new(true);
    f.positive();
    let pid = pid(&f);
    let expiry: i64 = f
        .client()
        .query_one(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=
         floor(extract(epoch FROM clock_timestamp())*1000000)::bigint+1000000
         WHERE proxy_id=$1 RETURNING expires_at_micros",
            &[f.input.proxy_id.as_uuid()],
        )
        .unwrap()
        .get(0);
    let expiry = u64::try_from(expiry).unwrap();
    let before = f.bytes();
    let mut blocker = f.client();
    let mut lock = blocker.transaction().unwrap();
    lock.batch_execute("LOCK TABLE mcp_proxy_revisions IN ACCESS EXCLUSIVE MODE")
        .unwrap();
    std::thread::scope(|scope| {
        let lookup = scope.spawn(|| f.read());
        let blocked = wait_for_lock(&f, pid, "FROM mcp_proxy_revisions");
        let mut clock = f.client();
        let arrived_before_expiry = database_now(&mut clock) < expiry;
        let deadline = Instant::now() + Duration::from_secs(2);
        while database_now(&mut clock) < expiry && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let expired = database_now(&mut clock) >= expiry;
        lock.rollback().unwrap();
        let result = lookup.join().unwrap();
        assert!(
            blocked && arrived_before_expiry,
            "must block at revision read after the initial live-lease check"
        );
        assert!(
            expired,
            "actual database clock must cross the stored expiry before releasing the read"
        );
        refused(result, REFUSED);
    });
    assert_eq!(f.bytes(), before);
}

#[test]
fn two_connection_takeover_race_retains_the_database_fence_and_refuses_stale_followup() {
    let f = Fixture::new(true);
    f.positive();
    let competitor = PostgresProxyStore::connect(&f.database.url).unwrap();
    f.execute(
        "UPDATE mcp_proxy_controller_leases SET expires_at_micros=
        floor(extract(epoch FROM clock_timestamp())*1000000)::bigint+50000 WHERE proxy_id=$1",
        &[f.input.proxy_id.as_uuid()],
    );
    let barrier = Barrier::new(2);
    let (read, taken) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            f.read()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(lease) = competitor
                    .lease_proxy_operation(
                        &f.input.scope,
                        &f.input.proxy_id,
                        "controller-b",
                        Duration::from_secs(30),
                    )
                    .unwrap()
                {
                    break lease;
                }
                assert!(
                    Instant::now() < deadline,
                    "database takeover never completed"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    match read {
        Ok(snapshot) => {
            assert_eq!(snapshot.fencing_token, 1);
            assert_eq!(snapshot.operation, f.operation);
            assert!(snapshot.checked_at_unix_us < snapshot.lease_expires_at_unix_us);
        }
        Err(error) => assert_eq!(error.code(), REFUSED),
    }
    assert_eq!(taken.fencing_token, 2);
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
    let before = f.bytes();
    let current = proto::RuntimeTarget {
        fencing_token: 2,
        ..f.target.clone()
    };
    let snapshot = competitor
        .read_current_runtime_operation(&current, &taken.operation.operation_id, "controller-b")
        .unwrap();
    assert_eq!(snapshot.worker_id, "controller-b");
    assert_eq!(snapshot.fencing_token, 2);
    assert_eq!(
        snapshot.lease_expires_at_unix_us,
        taken.lease_expires_at_micros
    );
    assert_eq!(f.bytes(), before);
}
