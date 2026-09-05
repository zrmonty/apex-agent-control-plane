use super::*;
use crate::proto;

fn snapshot() -> RuntimeAuthoritySnapshot {
    RuntimeAuthoritySnapshot {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
            revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            generation: 9_007_199_254_740_993,
            fencing_token: 9_007_199_254_740_995,
        }),
        operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
        command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
        action: 1,
        installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
        agent_identity_id: "client-agent".into(),
        observed_controller_identity_id: "client-controller".into(),
        peer_policy_version: "client-policy".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
        desired_state: 1,
        observed_state: 1,
        config_hash: "a".repeat(64),
        // Synthetic DB timestamps deliberately above the exact f64 integer range.
        checked_at_unix_us: 9_007_199_254_740_993,
        lease_expires_at_unix_us: 9_007_199_254_741_000,
    }
}

fn check(value: &RuntimeAuthoritySnapshot, elapsed: Duration) -> Result<(), AuthorityClientError> {
    let config = AuthorityClientConfig {
        endpoint: "https://unused.invalid".into(),
        tls_server_name: "unused.invalid".into(),
        ca_pem: vec![],
        client_certificate_pem: vec![],
        client_key_pem: vec![],
        installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
        agent_identity_id: "client-agent".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
    };
    let target = proto::RuntimeTarget {
        workspace_id: "work".into(),
        namespace_id: "ns".into(),
        proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
        revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
        generation: 9_007_199_254_740_993,
        fencing_token: 9_007_199_254_740_995,
    };
    validate(
        value,
        &config,
        &AuthorityOperation {
            target: &target,
            operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05",
            command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06",
            config_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        "client-controller",
        "client-policy",
        elapsed,
    )
}

#[test]
fn integer_microseconds_survive_without_float_or_remote_wall_clock_math() {
    // Catches millisecond/f64 conversion and local-minus-remote wall clock logic.
    for (expires, before_ns, at_ns) in [
        (9_007_199_254_740_994, 999, 1_000),
        (9_007_199_254_741_000, 6_999, 7_000),
        (9_007_199_254_741_992, 998_999, 999_000),
    ] {
        let mut value = snapshot();
        value.lease_expires_at_unix_us = expires;
        assert_eq!(check(&value, Duration::from_nanos(before_ns)), Ok(()));
        assert!(check(&value, Duration::from_nanos(at_ns)).is_err());
        assert!(check(&value, Duration::from_nanos(at_ns + 1)).is_err());
        assert!(check(&value, Duration::from_nanos(at_ns + 999)).is_err());
        assert_eq!(value.checked_at_unix_us, 9_007_199_254_740_993);
        assert_eq!(value.lease_expires_at_unix_us, expires);
    }
}

#[test]
fn each_snapshot_binding_is_required_independently() {
    // Catches omitted equality checks, including the often missed sixth target field.
    let changes: &[fn(&mut RuntimeAuthoritySnapshot)] = &[
        |s| s.schema_version = 2,
        |s| s.action = 0,
        |s| s.action = 99,
        |s| s.target = None,
        |s| s.target.as_mut().unwrap().workspace_id = "elsewhere".into(),
        |s| s.target.as_mut().unwrap().namespace_id = "elsewhere".into(),
        |s| s.target.as_mut().unwrap().proxy_id.replace_range(35.., "9"),
        |s| {
            s.target
                .as_mut()
                .unwrap()
                .revision_id
                .replace_range(35.., "9")
        },
        |s| s.target.as_mut().unwrap().generation += 1,
        |s| s.target.as_mut().unwrap().fencing_token += 1,
        |s| s.operation_id.replace_range(35.., "9"),
        |s| s.command_id.replace_range(35.., "9"),
        |s| s.installation_id.replace_range(35.., "9"),
        |s| s.agent_identity_id = "other-agent".into(),
        |s| s.observed_controller_identity_id = "other-controller".into(),
        |s| s.peer_policy_version = "other-policy".into(),
        |s| s.enrollment_version = "other-enrollment".into(),
        |s| s.host_policy_version = "other-host".into(),
        |s| s.config_hash = "b".repeat(64),
    ];
    assert_eq!(check(&snapshot(), Duration::ZERO), Ok(()));
    for change in changes {
        let mut value = snapshot();
        change(&mut value);
        assert!(check(&value, Duration::ZERO).is_err());
    }
}

#[test]
fn unspecified_unknown_enums_and_non_sql_timestamps_are_rejected() {
    // Catches accepting generated enum defaults/unknowns or overflowing SQL integers.
    assert_eq!(check(&snapshot(), Duration::ZERO), Ok(()));
    for invalid in [0, -1, i32::MAX] {
        let mut value = snapshot();
        value.desired_state = invalid;
        assert!(check(&value, Duration::ZERO).is_err());
        let mut value = snapshot();
        value.observed_state = invalid;
        assert!(check(&value, Duration::ZERO).is_err());
    }
    for (checked, expires) in [
        (0, 1),
        (1, 0),
        (7, 7),
        (8, 7),
        (1, 9_223_372_036_854_775_808),
        (9_223_372_036_854_775_808, u64::MAX),
        (u64::MAX, u64::MAX),
    ] {
        let mut value = snapshot();
        value.checked_at_unix_us = checked;
        value.lease_expires_at_unix_us = expires;
        assert!(check(&value, Duration::ZERO).is_err());
    }
    let mut edge = snapshot();
    edge.checked_at_unix_us = 9_223_372_036_854_775_806;
    edge.lease_expires_at_unix_us = 9_223_372_036_854_775_807;
    assert_eq!(check(&edge, Duration::from_nanos(999)), Ok(()));
}
