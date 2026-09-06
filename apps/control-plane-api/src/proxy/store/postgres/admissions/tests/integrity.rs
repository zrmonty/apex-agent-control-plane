use super::*;

#[test]
fn admittable_read_is_quota_free_and_refuses_prepare_unapplied_and_wrong_epoch() {
    let f = Fixture::new();
    let g = selected(&f);
    assert!(
        f.store
            .read_admittable_deployment_checked(&f.registration.binding, &|| Ok(()))
            .is_err()
    );
    renew(&f, 4, Some(&g), true);
    let record = f
        .store
        .read_admittable_deployment_checked(&f.registration.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(record.epoch, g.epoch);
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_admission_counters", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.client()
        .execute("UPDATE mcp_proxy_serving_selection SET epoch=epoch+1", &[])
        .unwrap();
    assert!(
        f.store
            .read_admittable_deployment_checked(&f.registration.binding, &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .is_err()
    );
}

#[test]
fn tombstones_issued_intervals_and_same_period_counters_cannot_reset() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    complete(&f, &input, &first);
    for sql in [
        "DELETE FROM mcp_proxy_call_admissions",
        "UPDATE mcp_proxy_call_admissions SET released=FALSE",
        "UPDATE mcp_proxy_call_admissions SET valid_until=valid_until+1",
        "DELETE FROM mcp_proxy_admission_counters",
        "UPDATE mcp_proxy_admission_counters SET minute_used=0",
        "UPDATE mcp_proxy_admission_counters SET day_used=0",
        "UPDATE mcp_proxy_admission_counters SET total_admissions=0",
    ] {
        assert!(f.client().execute(sql, &[]).is_err(), "{sql}");
    }
}

#[test]
fn absent_wrong_policy_or_forged_binding_never_counts_a_call() {
    let f = Fixture::new();
    serving(&f);
    for field in ["policy", "revision", "instance", "installation", "hash"] {
        let mut input = request(&f);
        match field {
            "policy" => input.policy_id = "other".into(),
            "revision" => input.policy_revision = 0,
            "instance" => input.binding.process_instance_id = Uuid::now_v7().to_string(),
            "installation" => input.binding.installation_id = Uuid::now_v7().to_string(),
            _ => input.binding.config_hash = "d".repeat(64),
        }
        assert!(
            f.store
                .reserve_managed_call_checked(&input, &|| Ok(()))
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

#[test]
fn admissions_schema_refuses_empty_newer_partial_and_unversioned_metadata() {
    for sql in [
        "TRUNCATE mcp_proxy_admissions_schema",
        "ALTER TABLE mcp_proxy_admissions_schema DROP CONSTRAINT mcp_proxy_admissions_schema_version_check; UPDATE mcp_proxy_admissions_schema SET version=2",
        "DROP TABLE mcp_proxy_call_admissions",
        "DROP TABLE mcp_proxy_admissions_schema",
    ] {
        let f = Fixture::new();
        f.client().batch_execute(sql).unwrap();
        assert!(PostgresProxyStore::connect(&f.url).is_err(), "{sql}");
    }
}

#[test]
fn current_publication_eligibility_is_rechecked_before_read_or_reservation() {
    let f = Fixture::new();
    serving(&f);
    f.client()
        .execute("UPDATE mcp_proxy_revisions SET is_published=FALSE", &[])
        .unwrap();
    assert!(
        f.store
            .read_admittable_deployment_checked(&f.registration.binding, &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .is_err()
    );
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
