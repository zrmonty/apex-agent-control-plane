use super::support::*;
use apex_control_plane_api::PostgresProxyStore;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn attempt_identity_is_durable_across_uncertain_retry_and_clock_skewed_restart() {
    let f = Fixture::new(true);
    let lease = f.lease.as_ref().unwrap();
    let first = f
        .store
        .prepare_runtime_attempt(lease)
        .expect("persist attempt before transport");
    assert_eq!(first.config_hash, f.revision.config_hash);
    assert_eq!(first.target.as_ref().unwrap(), &f.target);
    let restarted = PostgresProxyStore::connect(&f.database.url).unwrap();
    assert_eq!(restarted.prepare_runtime_attempt(lease).unwrap(), first);
    // A prior replica allocated in a future millisecond. No wall-clock authority
    // is inferred from this ID: after handoff the canonical selector must increase.
    let future = Uuid::parse_str("ffffffff-ffff-7ffe-bfff-fffffffffff0").unwrap();
    f.execute(
        "UPDATE mcp_proxy_runtime_attempts SET last_command_id=$2 WHERE proxy_id=$1",
        &[f.input.proxy_id.as_uuid(), &future],
    );
    f.expired_at_database_edge();
    let second_lease = restarted
        .lease_proxy_operation(
            &f.input.scope,
            &f.input.proxy_id,
            "controller-b",
            Duration::from_secs(180),
        )
        .unwrap()
        .unwrap();
    let second = restarted.prepare_runtime_attempt(&second_lease).unwrap();
    assert!(Uuid::parse_str(&second.command_id).unwrap() > future);
    assert_eq!(second.target.as_ref().unwrap().fencing_token, 2);
    assert!(f.store.prepare_runtime_attempt(lease).is_err());
    assert_eq!(
        restarted.prepare_runtime_attempt(&second_lease).unwrap(),
        second
    );
}
