use super::*;

fn prepared(
    f: &Fixture,
) -> (
    proto::ManagedDeploymentGrant,
    proto::ManagedDeploymentGrant,
    Uuid,
) {
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let d1 = f
        .store
        .renew_deployment_checked(&renewal(f, 1, None), &|| Ok(()))
        .unwrap();
    let d2 = f
        .store
        .renew_deployment_checked(&renewal(f, 2, Some(ack(&d1, false, 0))), &|| Ok(()))
        .unwrap();
    let observation = f
        .store
        .record_candidate_readiness_checked(
            &f.lease,
            &f.registration.binding,
            &ready(f),
            &|| Ok(()),
        )
        .unwrap();
    (d1, d2, observation)
}

#[test]
fn newer_prepare_busy_ack_refuses_selection_and_requires_fresh_readiness_after_drain() {
    let f = Fixture::new();
    let (_, d2, observation) = prepared(&f);
    let before = f.rows("mcp_proxy_serving_selection");
    // The exact review interleaving uses only real private store methods.
    let d3 = f
        .store
        .renew_deployment_checked(&renewal(&f, 3, Some(ack(&d2, false, 1))), &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
            .is_err(),
        "newer PREPARE physical activity must contradict the old readiness observation"
    );
    assert_eq!(before, f.rows("mcp_proxy_serving_selection"));
    let busy = f
        .store
        .read_deployment_checked(&f.registration.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(busy.active_calls, 1);
    assert_eq!(busy.mode, proto::ManagedGrantMode::Prepare);
    assert_eq!(busy.applied.unwrap().sequence, 2);
    assert!(f.client().query_one("SELECT readiness_id IS NULL AND readiness_bytes IS NULL AND readiness_until=0 AND readiness_fence=0 FROM mcp_proxy_deployments", &[]).unwrap().get::<_, bool>(0));
    // Actual later quiescence can clear the count, but cannot resurrect R.
    f.store
        .renew_deployment_checked(&renewal(&f, 4, Some(ack(&d3, false, 0))), &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
            .is_err()
    );
    assert_eq!(before, f.rows("mcp_proxy_serving_selection"));
    let fresh = f
        .store
        .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &ready(&f), &|| {
            Ok(())
        })
        .unwrap();
    assert_ne!(fresh, observation);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, fresh, &|| Ok(()))
        .unwrap();
}

#[test]
fn selection_rechecks_current_applied_state_even_with_retained_readiness() {
    // Component-only persisted-state fixtures also cover rows written by the
    // previous checkpoint, which retained readiness on contradictory progress.
    for change in [
        "active_calls=1",
        "applied_mode=2,admitting=TRUE",
        "applied_mode=3",
    ] {
        let f = Fixture::new();
        let (_, _, observation) = prepared(&f);
        f.client()
            .execute(&format!("UPDATE mcp_proxy_deployments SET {change}"), &[])
            .unwrap();
        let before = f.rows("mcp_proxy_serving_selection");
        let deployment = f.rows("mcp_proxy_deployments");
        assert!(
            f.store
                .select_candidate_checked(
                    &f.lease,
                    &f.registration.binding,
                    observation,
                    &|| Ok(())
                )
                .is_err(),
            "{change}"
        );
        assert_eq!(before, f.rows("mcp_proxy_serving_selection"));
        assert_eq!(deployment, f.rows("mcp_proxy_deployments"));
    }
}

#[test]
fn compatible_newer_prepare_and_stale_busy_ack_preserve_valid_readiness() {
    let f = Fixture::new();
    let (d1, d2, observation) = prepared(&f);
    f.store
        .renew_deployment_checked(&renewal(&f, 3, Some(ack(&d2, false, 0))), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 4, Some(ack(&d1, false, 1))), &|| Ok(()))
        .unwrap();
    let current = f
        .store
        .read_deployment_checked(&f.registration.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(current.active_calls, 0);
    assert_eq!(current.applied.unwrap().sequence, 2);
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, observation, &|| Ok(()))
        .unwrap();
}

#[test]
fn current_applied_prepare_must_remain_valid_through_selection_finish() {
    for delay in [false, true] {
        let f = Fixture::new();
        let (_, _, observation) = prepared(&f);
        // Keep a component-only readiness fixture live while the immutable
        // applied grant expires in real DB time. Never alter issued decisions.
        f.client().execute("UPDATE mcp_proxy_deployments SET readiness_until=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint+30000000", &[]).unwrap();
        if delay {
            // Sequence progress survives rollback and proves the trigger
            // completed after real expiry, not that SQL was timed out inside it.
            f.client()
                .batch_execute(
                    "CREATE SEQUENCE selection_delay_completed;
                 CREATE FUNCTION hold_selection() RETURNS trigger LANGUAGE plpgsql AS $$
                 DECLARE remaining DOUBLE PRECISION;
                 BEGIN
                   IF NEW.mode=2 THEN
                     SELECT (valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0
                       INTO STRICT remaining FROM mcp_proxy_grant_decisions
                       WHERE instance_id=NEW.instance_id AND sequence=NEW.applied_sequence;
                     IF remaining<=0 OR remaining>1.1 THEN
                       RAISE EXCEPTION 'test must enter selection with short positive validity';
                     END IF;
                     PERFORM pg_sleep(remaining+0.01);
                     PERFORM nextval('selection_delay_completed');
                   END IF;
                   RETURN NEW;
                 END $$;
                 CREATE TRIGGER hold_selection BEFORE UPDATE ON mcp_proxy_deployments
                   FOR EACH ROW EXECUTE FUNCTION hold_selection()",
                )
                .unwrap();
        } else {
            f.client().query_one("SELECT pg_sleep(GREATEST(0,(g.valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0)+0.01) FROM mcp_proxy_grant_decisions g JOIN mcp_proxy_deployments d ON g.instance_id=d.instance_id AND g.sequence=d.applied_sequence", &[]).unwrap();
        }
        let selection = f.rows("mcp_proxy_serving_selection");
        let deployment = f.rows("mcp_proxy_deployments");
        if delay {
            // Wait outside the store transaction until ~1s remains. The real
            // UPDATE then takes <1.11s, within the unchanged 5s statement limit.
            f.client().query_one("SELECT pg_sleep(GREATEST(0,(g.valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0-1.0)) FROM mcp_proxy_grant_decisions g JOIN mcp_proxy_deployments d ON g.instance_id=d.instance_id AND g.sequence=d.applied_sequence", &[]).unwrap();
        }
        let result = f.store.select_candidate_checked(
            &f.lease,
            &f.registration.binding,
            observation,
            &|| Ok(()),
        );
        if delay {
            assert!(
                f.client()
                    .query_one("SELECT is_called FROM selection_delay_completed", &[])
                    .unwrap()
                    .get::<_, bool>(0),
                "selection must finish its SQL after applied expiry, not fail an earlier check or statement timeout: {result:?}"
            );
        }
        let error = result.unwrap_err();
        assert_eq!(
            error.code(),
            "MANAGED_REGISTRY_REFUSED",
            "expired applied PREPARE must refuse, including after SQL delay={delay}"
        );
        assert_eq!(selection, f.rows("mcp_proxy_serving_selection"));
        assert_eq!(deployment, f.rows("mcp_proxy_deployments"));
    }
}
