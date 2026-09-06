use super::*;

#[test]
fn replica_contention_has_one_exact_identity_and_shared_physical_cap() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let stores = (0..8)
        .map(|_| PostgresProxyStore::connect(&f.url).unwrap())
        .collect::<Vec<_>>();
    let barrier = std::sync::Barrier::new(8);
    let results = std::thread::scope(|s| {
        stores
            .iter()
            .map(|store| {
                let b = &barrier;
                let i = &input;
                s.spawn(move || {
                    b.wait();
                    store.reserve_managed_call_checked(i, &|| Ok(())).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        results
            .iter()
            .all(|r| r.admission_id == results[0].admission_id)
    );
    assert_eq!(counters(&f), (1, 1, 1, 1));
    let results = std::thread::scope(|s| {
        stores
            .iter()
            .map(|store| {
                let b = &barrier;
                let i = request(&f);
                s.spawn(move || {
                    b.wait();
                    store.reserve_managed_call_checked(&i, &|| Ok(()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| e.code() == "MANAGED_ADMISSION_LIMIT")
    );
    assert_eq!(counters(&f), (4, 4, 4, 4));
}

#[test]
fn cancellation_after_actual_insert_rolls_back_reservation_and_all_counters() {
    let f = Fixture::new();
    serving(&f);
    f.client().batch_execute("CREATE SEQUENCE admission_inserted; CREATE FUNCTION mark_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('admission_inserted'); RETURN NEW; END $$; CREATE TRIGGER mark_admission AFTER INSERT ON mcp_proxy_call_admissions FOR EACH ROW EXECUTE FUNCTION mark_admission()").unwrap();
    let probe = std::sync::Mutex::new(f.client());
    let check = || {
        if probe
            .lock()
            .unwrap()
            .query_one("SELECT is_called FROM admission_inserted", &[])
            .unwrap()
            .get::<_, bool>(0)
        {
            Err(ProxyError::new("TEST_CANCELLED", "Cancelled."))
        } else {
            Ok(())
        }
    };
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&request(&f), &check)
            .unwrap_err()
            .code(),
        "TEST_CANCELLED"
    );
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_admission_counters", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

#[test]
fn cancellation_after_commit_is_durable_and_exact_retry_does_not_recount() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let probe = std::sync::Mutex::new(f.client());
    let check = || {
        if probe
            .lock()
            .unwrap()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0)
            > 0
        {
            Err(ProxyError::new("TEST_CANCELLED", "Cancelled."))
        } else {
            Ok(())
        }
    };
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&input, &check)
            .unwrap_err()
            .code(),
        "TEST_CANCELLED"
    );
    let stored: Uuid = f
        .client()
        .query_one("SELECT admission_id FROM mcp_proxy_call_admissions", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&input, &|| Ok(()))
            .unwrap()
            .admission_id,
        stored
    );
    assert_eq!(counters(&f), (1, 1, 1, 1));
}

#[test]
fn cancellation_after_completion_sql_retains_physical_capacity() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    f.client().batch_execute("CREATE SEQUENCE admission_released; CREATE FUNCTION mark_release() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('admission_released'); RETURN NEW; END $$; CREATE TRIGGER mark_release AFTER UPDATE ON mcp_proxy_call_admissions FOR EACH ROW EXECUTE FUNCTION mark_release()").unwrap();
    let probe = std::sync::Mutex::new(f.client());
    let check = || {
        if probe
            .lock()
            .unwrap()
            .query_one("SELECT is_called FROM admission_released", &[])
            .unwrap()
            .get::<_, bool>(0)
        {
            Err(ProxyError::new("TEST_CANCELLED", "Cancelled."))
        } else {
            Ok(())
        }
    };
    assert_eq!(
        f.store
            .complete_managed_call_checked(
                &input.binding,
                first.admission_id,
                input.call_id,
                &check
            )
            .unwrap_err()
            .code(),
        "TEST_CANCELLED"
    );
    assert_eq!(counters(&f), (1, 1, 1, 1));
    assert!(
        !f.client()
            .query_one("SELECT released FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, bool>(0)
    );
    complete(&f, &input, &first);
    assert_eq!(counters(&f), (1, 1, 0, 1));
}

#[test]
fn real_applied_expiry_after_insert_refuses_and_rolls_back_accounting() {
    let f = Fixture::new();
    serving(&f);
    f.client()
        .batch_execute(
            "CREATE SEQUENCE admission_delay_completed;
         CREATE FUNCTION hold_admission() RETURNS trigger LANGUAGE plpgsql AS $$
         DECLARE remaining DOUBLE PRECISION;
         BEGIN
           remaining:=(NEW.valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0;
           IF remaining<=0 OR remaining>1.1 THEN RAISE EXCEPTION 'invalid test timing'; END IF;
           PERFORM pg_sleep(remaining+0.01);
           PERFORM nextval('admission_delay_completed');
           RETURN NEW;
         END $$;
         CREATE TRIGGER hold_admission AFTER INSERT ON mcp_proxy_call_admissions
           FOR EACH ROW EXECUTE FUNCTION hold_admission()",
        )
        .unwrap();
    // No immutable row edits or connection/host timeout overrides. Wait outside
    // the store until the triggered SQL can finish inside its unchanged 5s cap.
    f.client().query_one("SELECT pg_sleep(GREATEST(0,(g.valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0-1)) FROM mcp_proxy_grant_decisions g JOIN mcp_proxy_deployments d ON g.instance_id=d.instance_id AND g.sequence=d.applied_sequence",&[]).unwrap();
    let error = f
        .store
        .reserve_managed_call_checked(&request(&f), &|| Ok(()))
        .unwrap_err();
    assert!(
        f.client()
            .query_one("SELECT is_called FROM admission_delay_completed", &[])
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(error.code(), "MANAGED_ADMISSION_REFUSED");
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_admission_counters", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
