//! Synthetic pins and deterministic time exercise shared policy logic only.
//! Actual transport evidence is separately tested by runtime_peer_pair.

use super::*;
use serde_json::{Value, json};

const INSTALL_A: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
const INSTALL_B: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
const AGENT: [u8; 32] = [0x11; 32];
const CONTROLLER: [u8; 32] = [0x22; 32];

fn grant(installation: &str, workspace: &str, namespace: &str) -> Value {
    json!({"installationId": installation, "workspaceId": workspace, "namespaceId": namespace})
}

fn document() -> Value {
    json!({
        "schemaVersion": 1, "version": "pair-policy-canary",
        "validFromUnixUs": "1", "expiresAtUnixUs": u64::MAX.to_string(),
        "peers": [
            {"certificateSha256": "11".repeat(32), "identityId": "agent-canary",
             "role": "agent", "revoked": false, "grants": [grant(INSTALL_A, "work", "ns")]},
            {"certificateSha256": "22".repeat(32), "identityId": "controller-canary",
             "role": "controller", "revoked": false, "grants": [grant(INSTALL_A, "work", "ns")]}
        ]
    })
}

fn parse(value: &Value) -> RuntimePeerPolicy {
    RuntimePeerPolicy::parse_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn check<'a>(
    policy: &'a RuntimePeerPolicy,
    agent: Option<[u8; 32]>,
    observed: &[u8; 32],
    grant: (&str, &str, &str),
    now: Result<u64, RuntimePeerError>,
) -> Result<RuntimePeerPair<'a>, RuntimePeerError> {
    let agent = agent.map(|certificate_sha256| PeerIdentity { certificate_sha256 });
    policy.authorize_agent_observation_at(agent.as_ref(), observed, grant, now)
}

fn positive(policy: &RuntimePeerPolicy) -> RuntimePeerPair<'_> {
    check(
        policy,
        Some(AGENT),
        &CONTROLLER,
        (INSTALL_A, "work", "ns"),
        Ok(7),
    )
    .unwrap()
}

#[test]
fn pair_keeps_agent_and_observed_controller_distinct_in_one_exact_grant() {
    let policy = parse(&document());
    let pair = positive(&policy);
    assert_eq!(pair.agent_identity_id(), "agent-canary");
    assert_eq!(pair.observed_controller_identity_id(), "controller-canary");
    assert_eq!(pair.installation_id(), INSTALL_A);
    assert_eq!((pair.workspace_id(), pair.namespace_id()), ("work", "ns"));
    assert_eq!(pair.policy_version(), "pair-policy-canary");
    assert_eq!(pair.checked_at_unix_us(), 7);
}

#[test]
fn one_supplied_private_time_sample_retains_microseconds_and_large_integers() {
    let policy = parse(&document());
    for time in [1, 7, 999, 9_007_199_254_740_993, u64::MAX - 1] {
        let pair = check(
            &policy,
            Some(AGENT),
            &CONTROLLER,
            (INSTALL_A, "work", "ns"),
            Ok(time),
        )
        .unwrap();
        assert_eq!(pair.checked_at_unix_us(), time);
    }
}

#[test]
fn rotation_of_either_leaf_keeps_only_the_registered_stable_identity() {
    let mut doc = document();
    for (index, pin) in [(0, "33"), (1, "44")] {
        let mut replacement = doc["peers"][index].clone();
        replacement["certificateSha256"] = json!(pin.repeat(32));
        doc["peers"].as_array_mut().unwrap().push(replacement);
    }
    let policy = parse(&doc);
    for agent in [AGENT, [0x33; 32]] {
        for controller in [CONTROLLER, [0x44; 32]] {
            let pair = check(
                &policy,
                Some(agent),
                &controller,
                (INSTALL_A, "work", "ns"),
                Ok(7),
            )
            .unwrap();
            assert_eq!(pair.agent_identity_id(), "agent-canary");
            assert_eq!(pair.observed_controller_identity_id(), "controller-canary");
        }
    }
}

#[test]
fn absent_actual_agent_cannot_be_replaced_by_a_known_observed_pin() {
    let policy = parse(&document());
    let error = check(&policy, None, &CONTROLLER, (INSTALL_A, "work", "ns"), Ok(7)).unwrap_err();
    assert_eq!(error, RuntimePeerError::Unauthenticated);
}

#[test]
fn controller_or_unknown_actual_caller_is_not_an_agent() {
    let policy = parse(&document());
    for caller in [CONTROLLER, [0x55; 32]] {
        assert_eq!(
            check(
                &policy,
                Some(caller),
                &CONTROLLER,
                (INSTALL_A, "work", "ns"),
                Ok(7)
            )
            .unwrap_err(),
            RuntimePeerError::Denied
        );
    }
}

#[test]
fn observed_agent_unknown_or_self_pin_is_not_a_controller() {
    let policy = parse(&document());
    for observed in [AGENT, [0x55; 32]] {
        assert_eq!(
            check(
                &policy,
                Some(AGENT),
                &observed,
                (INSTALL_A, "work", "ns"),
                Ok(7)
            )
            .unwrap_err(),
            RuntimePeerError::Denied
        );
    }
}

#[test]
fn revocation_of_either_leaf_refuses_even_when_the_other_leaf_matches() {
    for index in [0, 1] {
        let mut doc = document();
        doc["peers"][index]["revoked"] = json!(true);
        let policy = parse(&doc);
        assert_eq!(
            check(
                &policy,
                Some(AGENT),
                &CONTROLLER,
                (INSTALL_A, "work", "ns"),
                Ok(7)
            )
            .unwrap_err(),
            RuntimePeerError::Denied
        );
    }
}

#[test]
fn each_side_must_have_the_exact_installation_workspace_and_namespace() {
    for index in [0, 1] {
        for replacement in [
            grant(INSTALL_B, "work", "ns"),
            grant(INSTALL_A, "other", "ns"),
            grant(INSTALL_A, "work", "other"),
        ] {
            let mut doc = document();
            doc["peers"][index]["grants"] = json!([replacement]);
            let policy = parse(&doc);
            assert_eq!(
                check(
                    &policy,
                    Some(AGENT),
                    &CONTROLLER,
                    (INSTALL_A, "work", "ns"),
                    Ok(7)
                )
                .unwrap_err(),
                RuntimePeerError::Denied
            );
        }
    }
}

#[test]
fn shared_grant_sets_do_not_expand_into_cartesian_product_scopes() {
    let mut doc = document();
    for index in [0, 1] {
        doc["peers"][index]["grants"] = json!([
            grant(INSTALL_A, "work", "ns"),
            grant(INSTALL_B, "other", "space")
        ]);
    }
    let policy = parse(&doc);
    for claim in [
        (INSTALL_A, "other", "space"),
        (INSTALL_B, "work", "ns"),
        (INSTALL_A, "work", "space"),
    ] {
        assert_eq!(
            check(&policy, Some(AGENT), &CONTROLLER, claim, Ok(7)).unwrap_err(),
            RuntimePeerError::Denied
        );
    }
    for claim in [(INSTALL_A, "work", "ns"), (INSTALL_B, "other", "space")] {
        let pair = check(&policy, Some(AGENT), &CONTROLLER, claim, Ok(7)).unwrap();
        assert_eq!(
            (
                pair.installation_id(),
                pair.workspace_id(),
                pair.namespace_id()
            ),
            claim
        );
    }
}

#[test]
fn registrations_from_separate_policy_snapshots_cannot_be_combined() {
    let mut agent_only = document();
    agent_only["peers"].as_array_mut().unwrap().remove(1);
    let mut controller_only = document();
    controller_only["peers"].as_array_mut().unwrap().remove(0);
    for policy in [parse(&agent_only), parse(&controller_only)] {
        assert_eq!(
            check(
                &policy,
                Some(AGENT),
                &CONTROLLER,
                (INSTALL_A, "work", "ns"),
                Ok(7)
            )
            .unwrap_err(),
            RuntimePeerError::Denied
        );
    }
}

#[test]
fn malformed_selectors_are_not_normalized_or_defaulted() {
    let policy = parse(&document());
    for claim in [
        ("*", "work", "ns"),
        (INSTALL_A, "work/ns", "ns"),
        (INSTALL_A, "work", "*"),
        (INSTALL_A, " work", "ns"),
        (INSTALL_A, "work", "ns\n"),
    ] {
        assert_eq!(
            check(&policy, Some(AGENT), &CONTROLLER, claim, Ok(7)).unwrap_err(),
            RuntimePeerError::InvalidSelector
        );
    }
}

#[test]
fn pair_uses_the_checked_policy_window_including_exact_expiry() {
    let mut doc = document();
    doc["validFromUnixUs"] = json!("100");
    doc["expiresAtUnixUs"] = json!("1000");
    let policy = parse(&doc);
    for time in [99, 1000, u64::MAX] {
        assert_eq!(
            check(
                &policy,
                Some(AGENT),
                &CONTROLLER,
                (INSTALL_A, "work", "ns"),
                Ok(time)
            )
            .unwrap_err(),
            RuntimePeerError::PolicyNotCurrent
        );
    }
    for time in [100, 999] {
        assert_eq!(
            check(
                &policy,
                Some(AGENT),
                &CONTROLLER,
                (INSTALL_A, "work", "ns"),
                Ok(time)
            )
            .unwrap()
            .checked_at_unix_us(),
            time
        );
    }
}

#[test]
fn unavailable_clock_is_not_a_zero_or_default_check_time() {
    let policy = parse(&document());
    assert_eq!(
        check(
            &policy,
            Some(AGENT),
            &CONTROLLER,
            (INSTALL_A, "work", "ns"),
            Err(RuntimePeerError::ClockUnavailable)
        )
        .unwrap_err(),
        RuntimePeerError::ClockUnavailable
    );
}

#[test]
fn public_pair_method_ignores_forged_identity_headers_without_tls() {
    let policy = parse(&document());
    let mut request = tonic::Request::new(());
    for name in [
        "authorization",
        "x-runtime-role",
        "x-peer-certificate-sha256",
        "x-forwarded-client-cert",
    ] {
        request
            .metadata_mut()
            .insert(name, "agent-canary".parse().unwrap());
    }
    let error = policy
        .authorize_agent_observation(&request, &CONTROLLER, INSTALL_A, "work", "ns")
        .unwrap_err();
    assert_eq!(error, RuntimePeerError::Unauthenticated);
    assert!(std::error::Error::source(&error).is_none());
    assert!(!format!("{error} {error:?}").contains("canary"));
}

#[test]
fn debug_does_not_expose_identity_policy_grant_or_observed_certificate() {
    let policy = parse(&document());
    let pair = positive(&policy);
    let debug = format!("{pair:?}");
    assert!(debug.len() <= 128);
    for canary in [
        "agent-canary",
        "controller-canary",
        "pair-policy-canary",
        INSTALL_A,
        "work",
        "222222",
    ] {
        assert!(!debug.contains(canary));
    }
}
