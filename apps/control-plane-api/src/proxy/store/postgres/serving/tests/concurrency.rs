use super::*;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[test]
fn replica_selection_contention_has_one_winner() {
    let f = Fixture::new();
    let mut candidates = Vec::new();
    for i in 0..2 {
        let mut r = f.registration.clone();
        r.binding.process_instance_id = Uuid::now_v7().to_string();
        r.binding.launch_context_hash = format!("{}", i + 3).repeat(64);
        f.store
            .register_deployment_checked(&f.lease, &r, &|| Ok(()))
            .unwrap();
        let mut request = renewal(&f, 1, None);
        request.binding = Some(r.binding.clone());
        let pre = f
            .store
            .renew_deployment_checked(&request, &|| Ok(()))
            .unwrap();
        request.renewal_sequence = 2;
        request.applied = Some(ack(&pre, false, 0));
        f.store
            .renew_deployment_checked(&request, &|| Ok(()))
            .unwrap();
        let mut report = ready(&f);
        report.report.process_instance_id = r.binding.process_instance_id.clone();
        report.report.launch_context_hash = r.binding.launch_context_hash.clone();
        let id = f
            .store
            .record_candidate_readiness_checked(&f.lease, &r.binding, &report, &|| Ok(()))
            .unwrap();
        candidates.push((r.binding, id));
    }
    let gate = Arc::new(Barrier::new(2));
    let jobs: Vec<_> = candidates
        .into_iter()
        .map(|(binding, id)| {
            let store = PostgresProxyStore::connect(&f.url).unwrap();
            let gate = gate.clone();
            let lease = f.lease.clone();
            std::thread::spawn(move || {
                gate.wait();
                store.select_candidate_checked(&lease, &binding, id, &|| Ok(()))
            })
        })
        .collect();
    assert_eq!(
        jobs.into_iter()
            .map(|j| j.join().unwrap().is_ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert_eq!(
        f.client()
            .query_one(
                "SELECT count(*) FROM mcp_proxy_deployments WHERE mode=2",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[test]
fn cancelled_physical_sql_keeps_connection_owned_until_rollback() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let application = format!("serving_cancel_{}", Uuid::now_v7().simple());
    let owned = Arc::new(
        PostgresProxyStore::connect(&format!("{}&application_name={application}", f.url)).unwrap(),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut blocker = f.client();
    let mut lock = blocker.transaction().unwrap();
    lock.query_one("SELECT proxy_id FROM mcp_proxies FOR UPDATE", &[])
        .unwrap();
    let work = owned.clone();
    let cancel = cancelled.clone();
    let request = renewal(&f, 1, None);
    let job = std::thread::spawn(move || {
        work.renew_deployment_checked(&request, &|| {
            if cancel.load(Ordering::SeqCst) {
                Err(ProxyError::new("TEST_CANCELLED", "Cancelled."))
            } else {
                Ok(())
            }
        })
    });
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if f.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')",&[&application]).unwrap().get::<_,bool>(0){break;}
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    cancelled.store(true, Ordering::SeqCst);
    assert!(
        owned
            .renew_deployment_checked(&renewal(&f, 2, None), &|| Ok(()))
            .is_err(),
        "no replacement may acquire the physical connection"
    );
    assert!(!job.is_finished());
    lock.rollback().unwrap();
    assert_eq!(job.join().unwrap().unwrap_err().code(), "TEST_CANCELLED");
    assert!(f.rows("mcp_proxy_grant_decisions").is_empty());
    assert!(
        owned
            .renew_deployment_checked(&renewal(&f, 2, None), &|| Ok(()))
            .is_ok()
    );
}

#[test]
fn refusal_after_registration_sql_rolls_back_all_owned_rows() {
    let f = Fixture::new();
    let step = std::cell::Cell::new(0usize);
    // Locate every cancellation boundary using independent fixtures. A refused
    // precommit request leaves no registration or epoch; postcommit refusal can
    // leave one exact retryable registration, never a partial registry.
    let check = || {
        step.set(step.get() + 1);
        Ok(())
    };
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &check)
        .unwrap();
    for stop in 1..=step.get() {
        let case = Fixture::new();
        let n = std::cell::Cell::new(0usize);
        let result =
            case.store
                .register_deployment_checked(&case.lease, &case.registration, &|| {
                    n.set(n.get() + 1);
                    if n.get() == stop {
                        Err(ProxyError::new("TEST_CANCELLED", "Cancelled."))
                    } else {
                        Ok(())
                    }
                });
        assert!(result.is_err(), "checkpoint {stop}");
        let registrations = case.rows("mcp_proxy_deployments").len();
        assert_eq!(
            registrations,
            case.rows("mcp_proxy_serving_selection").len()
        );
        case.store
            .register_deployment_checked(&case.lease, &case.registration, &|| Ok(()))
            .unwrap();
        assert_eq!(case.rows("mcp_proxy_deployments").len(), 1);
    }
}
