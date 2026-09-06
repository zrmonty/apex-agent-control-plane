use super::*;

#[test]
fn expired_readiness_during_selection_rolls_back_selection_and_epoch() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let pre = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    let id = f
        .store
        .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &ready(&f), &|| {
            Ok(())
        })
        .unwrap();
    let before = f.rows("mcp_proxy_serving_selection");
    // Delay the actual selected-row mutation past the stored readiness interval.
    // The test-only trigger alters timing, not production validation or data.
    f.client().batch_execute("CREATE FUNCTION hold_selection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.mode=2 THEN PERFORM pg_sleep(0.15); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_selection BEFORE UPDATE ON mcp_proxy_deployments FOR EACH ROW EXECUTE FUNCTION hold_selection(); UPDATE mcp_proxy_deployments SET readiness_until=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint+100000").unwrap();
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, id, &|| Ok(()))
            .is_err(),
        "late SQL must not commit selection from expired readiness"
    );
    assert_eq!(before, f.rows("mcp_proxy_serving_selection"));
}

#[test]
fn first_registration_joins_configuration_scope_generation_and_published_spec() {
    let f = Fixture::new();
    for field in [
        "workspace",
        "namespace",
        "proxy",
        "revision",
        "generation",
        "hash",
        "spec",
    ] {
        let mut bad = f.registration.clone();
        match field {
            "workspace" => bad.configuration.workspace_id = "other".into(),
            "namespace" => bad.configuration.namespace_id = "other".into(),
            "proxy" => bad.configuration.proxy_id = Uuid::now_v7().to_string(),
            "revision" => bad.configuration.revision_id = Uuid::now_v7().to_string(),
            "generation" => bad.configuration.generation += 1,
            "hash" => {
                bad.binding.config_hash = "d".repeat(64);
                bad.configuration.config_hash = bad.binding.config_hash.clone();
            }
            "spec" => {
                bad.configuration
                    .spec
                    .as_mut()
                    .unwrap()
                    .governance_binding
                    .as_mut()
                    .unwrap()
                    .policy_id = "other".into()
            }
            _ => unreachable!(),
        }
        bad.configuration.runtime_manifest_hash =
            crate::proxy::runtime_manifest_hash(&bad.configuration).unwrap();
        assert!(
            f.store
                .register_deployment_checked(&f.lease, &bad, &|| Ok(()))
                .is_err(),
            "{field}"
        );
        assert!(f.rows("mcp_proxy_deployments").is_empty());
    }
}

#[test]
fn sequence_and_epoch_preserve_sql_range_above_javascript_safe_integer() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    f.client()
        .execute(
            "UPDATE mcp_proxy_serving_selection SET epoch=9007199254740993",
            &[],
        )
        .unwrap();
    let g = f
        .store
        .renew_deployment_checked(&renewal(&f, 9_007_199_254_740_993, None), &|| Ok(()))
        .unwrap();
    assert_eq!(g.epoch, 9_007_199_254_740_993);
    assert_eq!(g.renewal_sequence, 9_007_199_254_740_993);
    for sequence in [0, 1, i64::MAX as u64 + 1, u64::MAX] {
        assert!(
            f.store
                .renew_deployment_checked(&renewal(&f, sequence, None), &|| Ok(()))
                .is_err()
        );
    }
    let mut bad = renewal(&f, 9_007_199_254_740_994, None);
    bad.nonce.pop();
    assert!(f.store.renew_deployment_checked(&bad, &|| Ok(())).is_err());
}

#[test]
fn registration_rejects_changed_configuration_profile_scope_and_stale_fence_without_writes() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let before = f.rows("mcp_proxy_deployments");
    for field in ["configuration", "profile", "scope", "instance"] {
        let mut bad = f.registration.clone();
        match field {
            "configuration" => {
                bad.configuration.resource_url = "https://other.invalid/mcp".into();
                bad.configuration.runtime_manifest_hash =
                    crate::proxy::runtime_manifest_hash(&bad.configuration).unwrap();
            }
            "profile" => bad.authority_profile_version = "v2".into(),
            "scope" => bad.binding.target.as_mut().unwrap().namespace_id = "other".into(),
            "instance" => bad.binding.launch_context_hash = "c".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            f.store
                .register_deployment_checked(&f.lease, &bad, &|| Ok(()))
                .is_err(),
            "{field}"
        );
        assert_eq!(before, f.rows("mcp_proxy_deployments"));
    }
    let mut stale = f.lease.clone();
    stale.fencing_token += 1;
    assert!(
        f.store
            .register_deployment_checked(&stale, &f.registration, &|| Ok(()))
            .is_err()
    );
}

#[test]
fn higher_fence_adopts_registered_original_but_refuses_first_unknown_old_launch() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let before = f.rows("mcp_proxy_deployments");
    f.client()
        .execute(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0",
            &[],
        )
        .unwrap();
    let key = BindingKey::new(&f.registration.binding).unwrap();
    let new = f
        .store
        .lease_proxy_operation(
            &key.scope,
            &key.proxy,
            "controller-b",
            std::time::Duration::from_secs(300),
        )
        .unwrap()
        .unwrap();
    assert!(new.fencing_token > f.lease.fencing_token);
    f.store
        .register_deployment_checked(&new, &f.registration, &|| Ok(()))
        .unwrap();
    assert_eq!(before, f.rows("mcp_proxy_deployments"));
    let mut unknown = f.registration.clone();
    unknown.binding.process_instance_id = Uuid::now_v7().to_string();
    assert!(
        f.store
            .register_deployment_checked(&new, &unknown, &|| Ok(()))
            .is_err()
    );
}

#[test]
fn readiness_rejects_missing_or_nonpass_checks_and_forged_binding() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let pre = f
        .store
        .renew_deployment_checked(&renewal(&f, 1, None), &|| Ok(()))
        .unwrap();
    f.store
        .renew_deployment_checked(&renewal(&f, 2, Some(ack(&pre, false, 0))), &|| Ok(()))
        .unwrap();
    for index in 0..9 {
        let mut report = ready(&f);
        report.report.checks[index].status = 3;
        assert!(
            f.store
                .record_candidate_readiness_checked(
                    &f.lease,
                    &f.registration.binding,
                    &report,
                    &|| Ok(())
                )
                .is_err()
        );
    }
    let mut report = ready(&f);
    report.report.process_instance_id = Uuid::now_v7().to_string();
    assert!(
        f.store
            .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &report, &|| Ok(
                ()
            ))
            .is_err()
    );
    for (admitting, active_calls) in [(true, 0), (false, 1)] {
        let mut physical = ready(&f);
        physical.admitting = admitting;
        physical.active_calls = active_calls;
        assert!(
            f.store
                .record_candidate_readiness_checked(
                    &f.lease,
                    &f.registration.binding,
                    &physical,
                    &|| Ok(())
                )
                .is_err(),
            "a candidate with physical admission/work is not prepared"
        );
    }
    let id = f
        .store
        .record_candidate_readiness_checked(&f.lease, &f.registration.binding, &ready(&f), &|| {
            Ok(())
        })
        .unwrap();
    f.client()
        .execute("UPDATE mcp_proxy_deployments SET readiness_until=1", &[])
        .unwrap();
    assert!(
        f.store
            .select_candidate_checked(&f.lease, &f.registration.binding, id, &|| Ok(()))
            .is_err()
    );
}

#[test]
fn database_constraints_preserve_epoch_identity_and_closed_tombstones() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    for sql in [
        "DELETE FROM mcp_proxy_serving_selection",
        "UPDATE mcp_proxy_serving_selection SET epoch=0",
        "UPDATE mcp_proxy_serving_selection SET installation_id='01940000-0000-7000-8000-000000000003'",
        "DELETE FROM mcp_proxy_deployments",
        "UPDATE mcp_proxy_deployments SET proof_sha256=decode(repeat('ff',32),'hex')",
    ] {
        assert!(f.client().execute(sql, &[]).is_err(), "{sql}");
    }
    f.store
        .record_deployment_termination_checked(&f.lease, &f.registration.binding, &|| Ok(()))
        .unwrap();
    assert!(
        f.client()
            .execute(
                "UPDATE mcp_proxy_deployments SET mode=1,terminated=FALSE",
                &[]
            )
            .is_err()
    );
}
