//! Real PostgreSQL metadata boundaries; synthetic health is not production Serving.
use super::*;
use std::time::{Duration, Instant};

fn prepared() -> Fixture {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let grant = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&grant, false, 0))), &|| Ok(()))
        .unwrap();
    f
}

#[test]
fn expired_health_handoff_cannot_create_readiness() {
    let f = prepared();
    let before = f.rows("mcp_proxy_deployments");
    let mut sample = ready(&f);
    sample.expires = Instant::now();
    assert!(
        f.store
            .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &sample, &|| Ok(
                ()
            ))
            .is_err()
    );
    assert_eq!(before, f.rows("mcp_proxy_deployments"));
}

#[test]
fn persisted_readiness_is_capped_by_original_health_lifetime() {
    let f = prepared();
    let before: i64 = f
        .client()
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
            &[],
        )
        .unwrap()
        .get(0);
    let mut sample = ready(&f);
    sample.expires = Instant::now() + Duration::from_micros(750_999);
    f.store
        .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &sample, &|| Ok(()))
        .unwrap();
    let until: i64 = f
        .client()
        .query_one("SELECT readiness_until FROM mcp_proxy_deployments", &[])
        .unwrap()
        .get(0);
    assert!(
        until - before < 1_000_000,
        "readiness extended the subsecond health sample: {}us",
        until - before
    );
    assert!(until > before);
}

#[test]
fn expiry_at_each_database_checkpoint_rolls_back_readiness() {
    use std::cell::Cell;
    let f = prepared();
    let sample = ready(&f);
    let start = Instant::now();
    let count = Cell::new(0);
    let check = || {
        count.set(count.get() + 1);
        Ok(())
    };
    f.store
        .record_candidate_readiness_at_checked(
            &f.lease,
            &f.registration.binding,
            &sample,
            &check,
            &|| start,
        )
        .unwrap();
    // Two checks follow COMMIT (transaction finish and released client). Every
    // earlier boundary, including lock admission and final precommit, rolls back.
    let precommit = count.get() - 2;
    let before = f.rows("mcp_proxy_deployments");
    for expire_at in 1..=precommit {
        count.set(0);
        let now = || {
            if count.get() >= expire_at {
                sample.expires
            } else {
                start
            }
        };
        assert!(
            f.store
                .record_candidate_readiness_at_checked(
                    &f.lease,
                    &f.registration.binding,
                    &sample,
                    &check,
                    &now
                )
                .is_err(),
            "checkpoint {expire_at}"
        );
        assert_eq!(
            before,
            f.rows("mcp_proxy_deployments"),
            "checkpoint {expire_at}"
        );
    }
    assert!(precommit > 20, "exercise actual SQL and finish checks");
}

#[test]
fn remaining_health_uses_integer_floor_microseconds() {
    let f = prepared();
    let start = Instant::now();
    let mut sample = ready(&f);
    sample.expires = start + Duration::from_nanos(1_999);
    assert_eq!(sample.remaining_us(start).unwrap(), 1);
    assert!(
        sample
            .remaining_us(start + Duration::from_nanos(1_000))
            .is_err()
    );
    assert!(sample.remaining_us(sample.expires).is_err());
}

#[test]
fn replaced_lease_and_generation_cannot_redeem_original_health_readiness() {
    let mut f = prepared();
    let binding = f.registration.binding.clone();
    let sample = ready(&f);
    let id = f
        .store
        .record_candidate_readiness_checked(&f.lease, &binding, &sample, &|| Ok(()))
        .unwrap();
    f.client()
        .execute(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0",
            &[],
        )
        .unwrap();
    let key = BindingKey::new(&binding).unwrap();
    let next = f
        .store
        .lease_proxy_operation(
            &key.scope,
            &key.proxy,
            "replacement",
            Duration::from_secs(300),
        )
        .unwrap()
        .unwrap();
    assert!(next.fencing_token > f.lease.fencing_token);
    let before = f.rows("mcp_proxy_serving_selection");
    assert!(
        f.store
            .record_candidate_readiness_checked(&f.lease, &binding, &sample, &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &binding, id, &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .select_candidate_checked(&next, &binding, id, &|| Ok(()))
            .is_err(),
        "row was stamped with the original consumption fence"
    );
    f.advance(proto::ProxyDesiredState::Serving, true);
    assert!(
        f.store
            .record_candidate_readiness_checked(&f.lease, &binding, &sample, &|| Ok(()))
            .is_err(),
        "old launch must not become the new generation candidate"
    );
    assert_eq!(before, f.rows("mcp_proxy_serving_selection"));
}

#[test]
fn expiry_between_db_time_sample_and_write_cannot_restart_lifetime() {
    use std::cell::Cell;
    let f = prepared();
    let mut sample = ready(&f);
    let start = Instant::now();
    sample.expires = start + Duration::from_secs(5);
    let count = Cell::new(0);
    let now = || {
        count.set(count.get() + 1);
        // Advance once after initial admission, independently of how many SQL
        // checkpoints the implementation uses.
        if count.get() > 1 {
            start + Duration::from_secs(2)
        } else {
            start
        }
    };
    f.store
        .record_candidate_readiness_at_checked(
            &f.lease,
            &f.registration.binding,
            &sample,
            &|| Ok(()),
            &now,
        )
        .unwrap();
    let remaining: i64 = f
        .client()
        .query_one("SELECT readiness_until-floor(extract(epoch FROM clock_timestamp())*1000000)::bigint FROM mcp_proxy_deployments", &[])
        .unwrap()
        .get(0);
    assert!(
        (1..=3_000_000).contains(&remaining),
        "elapsed DB boundary time must reduce persisted readiness"
    );
}
