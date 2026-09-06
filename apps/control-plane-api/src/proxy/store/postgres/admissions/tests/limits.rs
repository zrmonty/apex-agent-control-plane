use super::*;

#[test]
fn published_concurrency_rate_and_daily_counters_are_independent_and_no_refund() {
    for (column, cap) in [
        ("active_calls", 4_i64),
        ("minute_used", 60),
        ("day_used", 5000),
        ("total_admissions", 1_000_000),
    ] {
        let f = Fixture::new();
        wait_for_accounting_window(&f);
        serving(&f);
        // Every successful admission must precede this actual applied expiry.
        // Refuse a delayed fixture setup rather than accepting a quota rollover
        // as an alternative to the exact limit assertion below.
        let row = f.client().query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint,g.valid_until FROM mcp_proxy_deployments d JOIN mcp_proxy_grant_decisions g ON g.instance_id=d.instance_id AND g.sequence=d.applied_sequence WHERE g.mode=2 AND d.applied_mode=2 AND d.admitting",
            &[],
        ).unwrap();
        let now: i64 = row.get(0);
        let until: i64 = row.get(1);
        assert!(until > now && until - now <= 10_000_000);
        assert_eq!(
            now / 60_000_000,
            (until - 1) / 60_000_000,
            "fixture's applied grant must fit in one accounting minute"
        );
        let input = request(&f);
        let first = f
            .store
            .reserve_managed_call_checked(&input, &|| Ok(()))
            .unwrap();
        complete(&f, &input, &first);
        assert_eq!(counters(&f), (1, 1, 0, 1));
        // Set only the disposable aggregate boundary; the actual published
        // immutable configuration still supplies the independently known caps.
        f.client()
            .execute(
                &format!("UPDATE mcp_proxy_admission_counters SET {column}=$1"),
                &[&cap],
            )
            .unwrap();
        let before = counters(&f);
        assert_eq!(
            f.store
                .reserve_managed_call_checked(&request(&f), &|| Ok(()))
                .unwrap_err()
                .code(),
            "MANAGED_ADMISSION_LIMIT",
            "{column}"
        );
        assert_eq!(counters(&f), before);
    }
}

fn wait_for_accounting_window(f: &Fixture) {
    let remaining = |client: &mut postgres::Client| -> i64 {
        client.query_one(
            "SELECT 60000000 - floor(extract(epoch FROM clock_timestamp())*1000000)::bigint % 60000000",
            &[],
        ).unwrap().get(0)
    };
    let mut client = f.client();
    let left = remaining(&mut client);
    if left <= 20_000_000 {
        // Conditional wait to a measured DB boundary, before issuing any grant.
        // No clock override, modified expiry or retry of the tested reservation.
        let seconds = f64::from(u32::try_from(left / 1_000_000 + 1).unwrap());
        client
            .query_one("SELECT pg_sleep($1)", &[&seconds])
            .unwrap();
    }
    assert!(
        remaining(&mut client) > 20_000_000,
        "fixture setup needs a full accounting window"
    );
}

#[test]
fn released_call_never_remints_and_changed_semantics_conflict() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    for field in ["hash", "policy", "revision"] {
        let mut changed = input.clone();
        match field {
            "hash" => changed.semantic_sha256 = [8; 32],
            "policy" => changed.policy_id = "other-policy".into(),
            _ => changed.policy_revision += 1,
        }
        assert_eq!(
            f.store
                .reserve_managed_call_checked(&changed, &|| Ok(()))
                .unwrap_err()
                .code(),
            "MANAGED_ADMISSION_CONFLICT"
        );
        assert_eq!(counters(&f), (1, 1, 1, 1));
    }
    complete(&f, &input, &first);
    complete(&f, &input, &first);
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&input, &|| Ok(()))
            .unwrap_err()
            .code(),
        "MANAGED_ADMISSION_REFUSED"
    );
    assert_eq!(counters(&f), (1, 1, 0, 1));
}

#[test]
fn immutable_expiry_never_releases_capacity_or_remints_call() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    f.store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    f.client().query_one("SELECT pg_sleep(GREATEST(0,(valid_until-extract(epoch FROM clock_timestamp())*1000000)/1000000.0)+0.01) FROM mcp_proxy_call_admissions",&[]).unwrap();
    let renewed = renew(&f, 5, None, true);
    renew(&f, 6, Some(&renewed), true);
    assert!(
        f.store
            .reserve_managed_call_checked(&input, &|| Ok(()))
            .is_err()
    );
    assert_eq!(counters(&f), (1, 1, 1, 1));
    for _ in 0..3 {
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .unwrap();
    }
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .unwrap_err()
            .code(),
        "MANAGED_ADMISSION_LIMIT"
    );
    assert_eq!(counters(&f).2, 4);
}

#[test]
fn policy_revision_preserves_full_unsigned_wire_range() {
    let f = Fixture::new();
    serving(&f);
    let mut input = request(&f);
    input.policy_revision = u64::MAX;
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    assert_eq!(first.policy_revision, u64::MAX);
    assert_eq!(
        f.store
            .reserve_managed_call_checked(&input, &|| Ok(()))
            .unwrap()
            .policy_revision,
        u64::MAX
    );
}

#[test]
fn utc_period_rollover_resets_only_its_own_usage_and_backward_time_refuses() {
    for prior_day in [false, true] {
        let f = Fixture::new();
        serving(&f);
        // Explicit component-only historical accounting fixture, never a host
        // clock change or update to a previously issued immutable decision.
        let day_offset: i64 = if prior_day { 1 } else { 0 };
        f.client().execute("INSERT INTO mcp_proxy_admission_counters SELECT proxy_id,floor(extract(epoch FROM clock_timestamp())/60)::bigint-1,60,floor(extract(epoch FROM clock_timestamp())/86400)::bigint-$1,10,0,100 FROM mcp_proxy_serving_selection",&[&day_offset]).unwrap();
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .unwrap();
        assert_eq!(counters(&f), (1, if prior_day { 1 } else { 11 }, 1, 101));
        f.client()
            .execute(
                "UPDATE mcp_proxy_admission_counters SET minute_bucket=minute_bucket+1",
                &[],
            )
            .unwrap();
        let before = counters(&f);
        assert!(
            f.store
                .reserve_managed_call_checked(&request(&f), &|| Ok(()))
                .is_err()
        );
        assert_eq!(counters(&f), before);
    }
}

#[test]
fn accounting_survives_revision_replacement_and_old_completion_cannot_release_new() {
    let mut f = Fixture::new();
    serving(&f);
    let old = request(&f);
    let admission = f
        .store
        .reserve_managed_call_checked(&old, &|| Ok(()))
        .unwrap();
    f.advance(proto::ProxyDesiredState::Serving, true);
    f.store
        .record_deployment_termination_checked(&f.lease, &old.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(
        f.store
            .release_terminated_admissions_checked(&old.binding, &|| Ok(()))
            .unwrap(),
        1
    );
    serving(&f);
    let new = request(&f);
    f.store
        .reserve_managed_call_checked(&new, &|| Ok(()))
        .unwrap();
    complete(&f, &old, &admission);
    assert_eq!(counters(&f), (2, 2, 1, 2));
}
