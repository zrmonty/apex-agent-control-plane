use super::*;

#[test]
fn selected_identity_view_is_exact_readonly_and_point_in_time() {
    let policy = parse(&document()).unwrap();
    let identity = peer();
    let checked = policy
        .authorize_at(Some(&identity), selection(INSTALL_A, "work", "ns"), Ok(7))
        .unwrap();
    assert_eq!(checked.identity_id(), IDENTITY);
    assert_eq!(checked.role(), RuntimePeerRole::Controller);
    assert_eq!(
        (
            checked.installation_id(),
            checked.workspace_id(),
            checked.namespace_id()
        ),
        (INSTALL_A, "work", "ns")
    );
    assert_eq!(checked.policy_version(), "policy-1");
    assert_eq!(checked.checked_at_unix_us(), 7);
    assert_eq!(
        format!("{checked:?}"),
        "AuthenticatedRuntimePeer { [point-in-time, redacted] }"
    );
}

#[test]
fn exact_grants_do_not_form_a_cartesian_product() {
    let mut input = document();
    input["peers"][0]["grants"] = json!([
        grant(INSTALL_A, "work", "ns"),
        grant(INSTALL_B, "other", "space")
    ]);
    let policy = parse(&input).unwrap();
    for (installation, workspace, namespace, allowed) in [
        (INSTALL_A, "work", "ns", true),
        (INSTALL_B, "other", "space", true),
        (INSTALL_A, "other", "space", false),
        (INSTALL_B, "work", "ns", false),
        (INSTALL_A, "work", "space", false),
        (INSTALL_A, "other", "ns", false),
    ] {
        let result = policy.authorize_at(
            Some(&peer()),
            selection(installation, workspace, namespace),
            Ok(7),
        );
        if allowed {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), RuntimePeerError::Denied);
        }
    }
}

#[test]
fn unknown_revoked_and_wrong_role_peers_are_refused() {
    let policy = parse(&document()).unwrap();
    let unknown = PeerIdentity {
        certificate_sha256: [0x22; 32],
    };
    assert_eq!(
        policy
            .authorize_at(Some(&unknown), selection(INSTALL_A, "work", "ns"), Ok(7))
            .unwrap_err(),
        RuntimePeerError::Denied
    );
    let mut wrong_role = selection(INSTALL_A, "work", "ns");
    wrong_role.role = RuntimePeerRole::Agent;
    assert_eq!(
        policy
            .authorize_at(Some(&peer()), wrong_role, Ok(7))
            .unwrap_err(),
        RuntimePeerError::Denied
    );
    let mut input = document();
    input["peers"][0]["revoked"] = json!(true);
    let revoked = parse(&input).unwrap();
    assert_eq!(
        revoked
            .authorize_at(Some(&peer()), selection(INSTALL_A, "work", "ns"), Ok(7))
            .unwrap_err(),
        RuntimePeerError::Denied
    );
}

#[test]
fn rotation_does_not_revive_old_revoked_leaf() {
    let mut input = document();
    input["peers"][0]["revoked"] = json!(true);
    let mut rotated = input["peers"][0].clone();
    rotated["certificateSha256"] = json!("22".repeat(32));
    rotated["revoked"] = json!(false);
    input["peers"].as_array_mut().unwrap().push(rotated);
    let policy = parse(&input).unwrap();
    assert_eq!(
        policy
            .authorize_at(Some(&peer()), selection(INSTALL_A, "work", "ns"), Ok(7))
            .unwrap_err(),
        RuntimePeerError::Denied
    );
    let replacement = PeerIdentity {
        certificate_sha256: [0x22; 32],
    };
    let checked = policy
        .authorize_at(
            Some(&replacement),
            selection(INSTALL_A, "work", "ns"),
            Ok(7),
        )
        .unwrap();
    assert_eq!(checked.identity_id(), IDENTITY);
}

#[test]
fn selectors_are_validated_without_scope_normalization() {
    let policy = parse(&document()).unwrap();
    for query in [
        selection("*", "work", "ns"),
        selection(INSTALL_A, "work/ns", "ns"),
        selection(INSTALL_A, "work", "*"),
        selection(INSTALL_A, "work", "ns\0"),
    ] {
        assert_eq!(
            policy
                .authorize_at(Some(&peer()), query, Ok(7))
                .unwrap_err(),
            RuntimePeerError::InvalidSelector
        );
    }
    assert_eq!(
        policy
            .authorize_at(Some(&peer()), selection(INSTALL_A, "Work", "ns"), Ok(7))
            .unwrap_err(),
        RuntimePeerError::Denied
    );
}

#[test]
fn clock_window_is_rechecked_with_inclusive_start_exclusive_expiry() {
    let mut input = document();
    input["validFromUnixUs"] = json!("7");
    input["expiresAtUnixUs"] = json!("999");
    let policy = parse(&input).unwrap();
    for (now, accepted) in [
        (0, false),
        (6, false),
        (7, true),
        (998, true),
        (999, false),
        (1000, false),
    ] {
        let checked =
            policy.authorize_at(Some(&peer()), selection(INSTALL_A, "work", "ns"), Ok(now));
        if accepted {
            assert_eq!(checked.unwrap().checked_at_unix_us(), now);
        } else {
            assert_eq!(checked.unwrap_err(), RuntimePeerError::PolicyNotCurrent);
        }
    }
    assert_eq!(
        policy
            .authorize_at(
                Some(&peer()),
                selection(INSTALL_A, "work", "ns"),
                Err(RuntimePeerError::ClockUnavailable)
            )
            .unwrap_err(),
        RuntimePeerError::ClockUnavailable
    );
}

#[test]
fn large_integer_timestamps_never_round_through_float() {
    let mut input = document();
    input["validFromUnixUs"] = json!("9007199254740993");
    let policy = parse(&input).unwrap();
    assert_eq!(
        policy
            .authorize_at(
                Some(&peer()),
                selection(INSTALL_A, "work", "ns"),
                Ok(9_007_199_254_740_992)
            )
            .unwrap_err(),
        RuntimePeerError::PolicyNotCurrent
    );
    let checked = policy
        .authorize_at(
            Some(&peer()),
            selection(INSTALL_A, "work", "ns"),
            Ok(9_007_199_254_740_993),
        )
        .unwrap();
    assert_eq!(checked.checked_at_unix_us(), 9_007_199_254_740_993);
    assert_eq!(
        policy
            .authorize_at(
                Some(&peer()),
                selection(INSTALL_A, "work", "ns"),
                Ok(u64::MAX)
            )
            .unwrap_err(),
        RuntimePeerError::PolicyNotCurrent
    );
}

#[test]
fn missing_clock_and_microsecond_overflow_refuse_without_sentinel_time() {
    assert_eq!(checked_clock(None), Err(RuntimePeerError::ClockUnavailable));
    assert_eq!(
        checked_clock(Some(Duration::new(u64::MAX, 999_999_999))),
        Err(RuntimePeerError::ClockUnavailable)
    );
    for micros in [1, 7, 999, 9_007_199_254_740_993] {
        assert_eq!(
            checked_clock(Some(Duration::from_micros(micros))),
            Ok(micros)
        );
    }
    assert_eq!(checked_clock(Some(Duration::from_nanos(1_999))), Ok(1));
}

#[test]
fn public_request_api_rejects_spoofed_metadata_and_plain_peer_extensions() {
    let policy = parse(&document()).unwrap();
    let mut request = tonic::Request::new(());
    for name in [
        "authorization",
        "x-peer-certificate-sha256",
        "x-runtime-role",
        "x-runtime-identity",
    ] {
        request
            .metadata_mut()
            .insert(name, "spoofed-canary".parse().unwrap());
    }
    // This ordinary extension is not TLS connection evidence. Do not fabricate
    // a TlsConnectInfo; the independent integration tests exercise actual TLS.
    request.extensions_mut().insert(peer());
    assert_eq!(
        policy
            .authorize(
                &request,
                RuntimePeerRole::Controller,
                INSTALL_A,
                "work",
                "ns"
            )
            .unwrap_err(),
        RuntimePeerError::Unauthenticated
    );
    assert_eq!(
        policy
            .authorize_at(None, selection(INSTALL_A, "work", "ns"), Ok(7))
            .unwrap_err(),
        RuntimePeerError::Unauthenticated
    );
}
