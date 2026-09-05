use std::time::{Duration, Instant};

use serde_json::json;

use super::super::RuntimeAuthorityError;
use super::super::enrollment::EnrollmentSelection;
use super::super::policy::PolicyState;
use super::support::{INSTALLATION, bytes, enrollment, peer_policy};

#[test]
fn initial_pair_publication_is_atomic_and_identical_refresh_keeps_generation() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    assert!(matches!(
        state.current(at),
        Err(RuntimeAuthorityError::Unavailable)
    ));
    let peer = bytes(&peer_policy());
    let enrollment = bytes(&enrollment());
    state
        .publish(&peer, &enrollment, at, at)
        .expect("valid component pair");
    let first = state.current(at).unwrap();
    assert_eq!(first.peer.version(), "policy-1");
    assert_eq!(first.enrollment.version(), "enrollment-1");
    let next = at + Duration::from_secs(1);
    state.publish(&peer, &enrollment, next, next).unwrap();
    assert_eq!(state.current(next).unwrap().generation, first.generation);
    assert!(state.recheck(&first, next).is_ok());
    assert!(state.current(at + Duration::from_millis(2999)).is_ok());
}

#[test]
fn freshness_expires_independently_of_refresh_or_timer_polling() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    state
        .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, at)
        .unwrap();
    let selected = state.current(at).unwrap();
    assert!(state.current(at + Duration::from_millis(1999)).is_ok());
    let expired = at + Duration::from_secs(2);
    assert!(matches!(
        state.current(expired),
        Err(RuntimeAuthorityError::Unavailable)
    ));
    assert!(state.recheck(&selected, expired).is_err());
}

#[test]
fn freshness_starts_before_read_and_late_or_reversed_reads_cannot_publish() {
    let at = Instant::now();
    for finished in [at + Duration::from_secs(2), at + Duration::from_secs(10)] {
        let mut state = PolicyState::new();
        assert!(
            state
                .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, finished)
                .is_err()
        );
        assert!(state.current(finished).is_err());
    }
    let mut state = PolicyState::new();
    assert!(
        state
            .publish(
                &bytes(&peer_policy()),
                &bytes(&enrollment()),
                at + Duration::from_secs(1),
                at
            )
            .is_err()
    );
    assert!(state.current(at).is_err());
}

#[test]
fn mixed_versions_or_invalid_refresh_disable_the_previously_valid_pair() {
    for case in 0..3 {
        let mut state = PolicyState::new();
        let at = Instant::now();
        state
            .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, at)
            .unwrap();
        let old = state.current(at).unwrap();
        let peer = if case == 1 {
            b"{".to_vec()
        } else {
            bytes(&peer_policy())
        };
        let mut wrong = enrollment();
        if case == 0 {
            wrong["peerPolicyVersion"] = json!("policy-not-loaded");
        }
        let enrollment = if case == 2 {
            b"{".to_vec()
        } else {
            bytes(&wrong)
        };
        assert!(state.publish(&peer, &enrollment, at, at).is_err());
        assert!(state.current(at).is_err());
        assert!(state.recheck(&old, at).is_err());
    }
}

#[test]
fn explicit_disable_does_not_revive_an_inflight_generation_on_recovery() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    let peer = bytes(&peer_policy());
    let enrollment = bytes(&enrollment());
    state.publish(&peer, &enrollment, at, at).unwrap();
    let old = state.current(at).unwrap();
    state.disable();
    assert!(state.current(at).is_err());
    state.publish(&peer, &enrollment, at, at).unwrap();
    let recovered = state.current(at).unwrap();
    assert_ne!(recovered.generation, old.generation);
    assert!(matches!(
        state.recheck(&old, at),
        Err(RuntimeAuthorityError::PolicyChanged)
    ));
}

#[test]
fn changed_versions_replace_and_refuse_a_previously_selected_generation() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    state
        .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, at)
        .unwrap();
    let old = state.current(at).unwrap();
    let mut peer = peer_policy();
    let mut enrollment = enrollment();
    peer["version"] = json!("policy-2");
    enrollment["version"] = json!("enrollment-2");
    enrollment["peerPolicyVersion"] = json!("policy-2");
    state
        .publish(&bytes(&peer), &bytes(&enrollment), at, at)
        .unwrap();
    let new = state.current(at).unwrap();
    assert_eq!(new.peer.version(), "policy-2");
    assert_eq!(new.enrollment.version(), "enrollment-2");
    assert_ne!(old.generation, new.generation);
    assert!(matches!(
        state.recheck(&old, at),
        Err(RuntimeAuthorityError::PolicyChanged)
    ));
    assert!(state.recheck(&new, at).is_ok());
}

#[test]
fn same_peer_version_changed_content_refuses_even_after_source_disable() {
    for disable in [false, true] {
        let mut state = PolicyState::new();
        let at = Instant::now();
        state
            .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, at)
            .unwrap();
        if disable {
            state.disable();
        }
        let mut changed = peer_policy();
        changed["peers"][0]["revoked"] = json!(true);
        let mut enrollment = enrollment();
        enrollment["version"] = json!("enrollment-2");
        assert!(
            state
                .publish(&bytes(&changed), &bytes(&enrollment), at, at)
                .is_err()
        );
        assert!(state.current(at).is_err());
    }
}

#[test]
fn same_enrollment_version_changed_content_refuses_even_after_source_disable() {
    for disable in [false, true] {
        let mut state = PolicyState::new();
        let at = Instant::now();
        state
            .publish(&bytes(&peer_policy()), &bytes(&enrollment()), at, at)
            .unwrap();
        if disable {
            state.disable();
        }
        let mut changed = enrollment();
        changed["installations"][0]["revoked"] = json!(true);
        assert!(
            state
                .publish(&bytes(&peer_policy()), &bytes(&changed), at, at)
                .is_err()
        );
        assert!(state.current(at).is_err());
    }
}

#[test]
fn enrollment_version_can_replace_independently_without_requiring_peer_version_change() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    let peer = bytes(&peer_policy());
    state.publish(&peer, &bytes(&enrollment()), at, at).unwrap();
    let old = state.current(at).unwrap();
    let mut changed = enrollment();
    changed["version"] = json!("enrollment-2");
    changed["installations"][0]["revoked"] = json!(true);
    state.publish(&peer, &bytes(&changed), at, at).unwrap();
    let new = state.current(at).unwrap();
    assert_ne!(new.generation, old.generation);
    assert_eq!(new.peer.version(), "policy-1");
    assert_eq!(new.enrollment.version(), "enrollment-2");
    let selector = EnrollmentSelection {
        peer_policy_version: "policy-1",
        agent_identity_id: "agent-a",
        observed_controller_identity_id: "controller-a",
        installation_id: INSTALLATION,
        workspace_id: "work",
        namespace_id: "ns",
        checked_at_unix_us: 100,
    };
    assert!(old.enrollment.select(selector).is_ok());
    assert!(matches!(
        new.enrollment.select(selector),
        Err(RuntimeAuthorityError::EnrollmentDenied)
    ));
}
