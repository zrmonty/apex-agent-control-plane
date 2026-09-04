// Startup tests for limits.

#[test]
fn admission_limit_is_range_checked_rather_than_clamped() {
    assert_eq!(admission_limit_value(None).unwrap(), 50);
    assert_eq!(admission_limit_value(Some("")).unwrap(), 50);
    assert_eq!(admission_limit_value(Some("1")).unwrap(), 1);
    assert_eq!(admission_limit_value(Some("100000")).unwrap(), 100_000);
    // Zero admits nothing and is far more likely a typo than an intent to
    // disable the control entirely.
    assert!(admission_limit_value(Some("0")).is_err());
    assert!(admission_limit_value(Some("100001")).is_err());
    assert!(admission_limit_value(Some("-1")).is_err());
    assert!(admission_limit_value(Some("fifty")).is_err());
}

/// The per-scope inbox quota is the per-tenant-fairness fix's configuration
/// knob: it must default sensibly, accept an explicit in-range value, and
/// fail closed -- never silently clamp -- on zero or on anything wider than
/// the capacity it is supposed to sit inside of.
#[test]
fn inbox_scope_quota_defaults_sensibly_and_is_bounded_by_capacity() {
    assert_eq!(inbox_scope_quota_value(None, 1_000_000).unwrap(), 20_000);
    assert_eq!(
        inbox_scope_quota_value(Some(""), 1_000_000).unwrap(),
        20_000
    );
    assert_eq!(inbox_scope_quota_value(Some("1"), 1_000_000).unwrap(), 1);
    assert_eq!(
        inbox_scope_quota_value(Some("1000000"), 1_000_000).unwrap(),
        1_000_000
    );
    // A capacity smaller than the default quota must not silently widen the
    // quota past the capacity it has to sit inside of; the default is
    // clamped down, not the other way around.
    assert_eq!(inbox_scope_quota_value(None, 100).unwrap(), 100);

    // Zero admits nothing for anybody in the scope, which is never what an
    // operator setting this variable meant -- refused, not treated as
    // "unlimited".
    assert!(inbox_scope_quota_value(Some("0"), 1_000_000).is_err());
    // Wider than the global capacity: refused rather than silently clamped
    // down to it, so a misconfiguration is loud at startup.
    assert!(inbox_scope_quota_value(Some("1000001"), 1_000_000).is_err());
    assert!(inbox_scope_quota_value(Some("-1"), 1_000_000).is_err());
    assert!(inbox_scope_quota_value(Some("twenty-thousand"), 1_000_000).is_err());
}

/// The control gateway must be given its own Valkey credentials and instance,
/// for the same reason it has its own NATS account and its own Postgres
/// database -- and, concretely, because `event-ingest`'s Valkey key prefix is
/// a fixed literal, so a shared instance is a shared keyspace under one ACL
/// user.
#[test]
fn ingest_valkey_configuration_is_refused_on_the_control_gateway() {
    assert_eq!(control_valkey_host_value(None, None).unwrap(), None);
    assert_eq!(
        control_valkey_host_value(Some("control-valkey"), None).unwrap(),
        Some("control-valkey".to_owned())
    );
    assert!(control_valkey_host_value(None, Some("valkey")).is_err());
    assert!(control_valkey_host_value(Some("control-valkey"), Some("valkey")).is_err());
}

#[test]
fn bounded_seconds_values_fail_closed_outside_their_range() {
    let message = "bad";
    assert_eq!(
        bounded_secs_value(None, 300, 30, 3600, message).unwrap(),
        std::time::Duration::from_secs(300)
    );
    assert!(bounded_secs_value(Some("30"), 300, 30, 3600, message).is_ok());
    assert!(bounded_secs_value(Some("3600"), 300, 30, 3600, message).is_ok());
    assert!(bounded_secs_value(Some("29"), 300, 30, 3600, message).is_err());
    assert!(bounded_secs_value(Some("3601"), 300, 30, 3600, message).is_err());
    assert!(bounded_secs_value(Some("0"), 300, 30, 3600, message).is_err());
    assert!(bounded_secs_value(Some("nope"), 300, 30, 3600, message).is_err());
}

#[test]
fn fanout_interval_defaults_to_the_ingest_replay_cadence_and_is_bounded() {
    use std::time::Duration;

    // Unset and empty both mean "the default", which is deliberately the same
    // 5s `event-ingest`'s own outbox replay worker uses.
    assert_eq!(
        fanout_interval_value(None).unwrap(),
        Duration::from_secs(5),
        "the default must stay pinned to event-ingest's replay cadence"
    );
    assert_eq!(
        fanout_interval_value(Some("")).unwrap(),
        Duration::from_secs(5)
    );
    assert_eq!(
        fanout_interval_value(Some("1")).unwrap(),
        Duration::from_secs(1)
    );
    assert_eq!(
        fanout_interval_value(Some("3600")).unwrap(),
        Duration::from_secs(3600)
    );

    // Zero is the one that matters: a zero-interval sleep is a busy loop that
    // would take and release the outbox mutex the accept path shares as fast
    // as the scheduler allows.
    assert!(fanout_interval_value(Some("0")).is_err());
    assert!(fanout_interval_value(Some("3601")).is_err());
    for bad in ["-1", "5s", "five", "1.5", " 5"] {
        assert!(
            fanout_interval_value(Some(bad)).is_err(),
            "{bad:?} must not parse as a fanout interval"
        );
    }
}

#[test]
fn nats_retry_attempts_matches_the_transport_ceiling() {
    assert_eq!(nats_retry_attempts_value(None).unwrap(), 3);
    assert_eq!(nats_retry_attempts_value(Some("")).unwrap(), 3);
    assert_eq!(nats_retry_attempts_value(Some("1")).unwrap(), 1);
    // 8 is `RetryingJetStreamTransport::new`'s own hard ceiling; anything the
    // env accepts past it would be refused later, at first publish, as an
    // opaque INVALID_RETRY_CONFIGURATION rather than at startup.
    assert_eq!(nats_retry_attempts_value(Some("8")).unwrap(), 8);
    assert!(nats_retry_attempts_value(Some("0")).is_err());
    assert!(nats_retry_attempts_value(Some("9")).is_err());
    assert!(nats_retry_attempts_value(Some("three")).is_err());
}

#[test]
fn command_retention_is_bounded_and_defaults_to_thirty_days() {
    use std::time::Duration;

    assert_eq!(
        command_retention_value(None).unwrap(),
        Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert_eq!(
        command_retention_value(Some("3600")).unwrap(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        command_retention_value(Some("31536000")).unwrap(),
        Duration::from_secs(31536000)
    );
    for bad in ["", "3599", "31536001", "three", "1.5", " 3600"] {
        if bad.is_empty() {
            assert_eq!(
                command_retention_value(Some(bad)).unwrap(),
                Duration::from_secs(30 * 24 * 60 * 60)
            );
        } else {
            assert!(command_retention_value(Some(bad)).is_err(), "{bad:?}");
        }
    }
}

#[test]
fn control_postgres_url_is_this_crate_s_own_variable() {
    assert_eq!(control_postgres_url_value(None, None).unwrap(), None);
    assert_eq!(
        control_postgres_url_value(Some("postgres://apex@db/control"), None).unwrap(),
        Some("postgres://apex@db/control".to_owned())
    );

    // `apex_durability::PostgresOutbox` hardcodes the `apex_event_outbox`
    // table name, so honouring event-ingest's variable here would silently
    // point the control gateway at the ingest gateway's outbox table -- where
    // each service's replay worker would claim and republish the other's rows
    // through its own sinks. Both of these must fail closed.
    assert!(control_postgres_url_value(None, Some("postgres://apex@db/apex")).is_err());
    assert!(
        control_postgres_url_value(
            Some("postgres://apex@db/control"),
            Some("postgres://apex@db/apex")
        )
        .is_err()
    );
}
