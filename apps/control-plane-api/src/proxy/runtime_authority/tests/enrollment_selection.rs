use serde_json::json;

use super::super::RuntimeAuthorityError;
use super::super::enrollment::{Enrollment, EnrollmentSelection};
use super::support::{INSTALLATION, bytes, enrollment};

// Private pure component selector; not a manufactured public RuntimePeerPair.
fn selection() -> EnrollmentSelection<'static> {
    EnrollmentSelection {
        peer_policy_version: "policy-1",
        agent_identity_id: "agent-a",
        observed_controller_identity_id: "controller-a",
        installation_id: INSTALLATION,
        workspace_id: "work",
        namespace_id: "ns",
        checked_at_unix_us: 100,
    }
}

#[test]
fn exact_enrollment_resolves_only_its_explicit_controller_worker_and_host_policy() {
    let mut value = enrollment();
    value["controllers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"identityId":"controller-b","workerId":"worker-b"}));
    let parsed = Enrollment::parse_json(&bytes(&value)).expect("valid component enrollment");
    let first = parsed.select(selection()).expect("exact binding");
    assert_eq!(first.worker_id, "worker-a");
    assert_eq!(first.host_policy_version, "host-policy-1");
    assert_eq!(first.enrollment_version, "enrollment-1");
    let second = parsed
        .select(EnrollmentSelection {
            observed_controller_identity_id: "controller-b",
            ..selection()
        })
        .expect("second explicit binding");
    assert_eq!(second.worker_id, "worker-b");
}

#[test]
fn journal_worker_punctuation_is_preserved_without_domain_normalization() {
    // Main's source/spec correction: the journal permits these exact workers.
    // Unlike domain IDs, workers deliberately have no additional '..' rule.
    for worker in ["a..b", ":", "_", "."] {
        let mut value = enrollment();
        value["controllers"][0]["workerId"] = json!(worker);
        let parsed = Enrollment::parse_json(&bytes(&value)).expect("valid journal worker");
        let binding = parsed
            .select(selection())
            .expect("exact configured mapping");
        assert_eq!(binding.worker_id, worker);
    }
}

#[test]
fn enrollment_refuses_each_wrong_binding_with_all_other_selectors_valid() {
    let parsed = Enrollment::parse_json(&bytes(&enrollment())).expect("valid component enrollment");
    assert!(parsed.select(selection()).is_ok());
    for denied in [
        EnrollmentSelection {
            peer_policy_version: "policy-2",
            ..selection()
        },
        EnrollmentSelection {
            agent_identity_id: "agent-b",
            ..selection()
        },
        EnrollmentSelection {
            observed_controller_identity_id: "unmapped",
            ..selection()
        },
        EnrollmentSelection {
            installation_id: "018f3d4a-8b9c-7d0e-8f12-ffffffffffff",
            ..selection()
        },
        EnrollmentSelection {
            workspace_id: "other",
            ..selection()
        },
        EnrollmentSelection {
            namespace_id: "other",
            ..selection()
        },
        EnrollmentSelection {
            checked_at_unix_us: 99,
            ..selection()
        },
        EnrollmentSelection {
            checked_at_unix_us: 1000,
            ..selection()
        },
    ] {
        assert!(matches!(
            parsed.select(denied),
            Err(RuntimeAuthorityError::EnrollmentDenied)
        ));
    }
    assert!(
        parsed
            .select(EnrollmentSelection {
                checked_at_unix_us: 999,
                ..selection()
            })
            .is_ok()
    );
}

#[test]
fn installation_revocation_is_independent_of_valid_peer_or_controller_mapping() {
    let mut value = enrollment();
    let before = Enrollment::parse_json(&bytes(&value)).unwrap();
    assert!(before.select(selection()).is_ok());
    value["installations"][0]["revoked"] = json!(true);
    let revoked = Enrollment::parse_json(&bytes(&value)).expect("revoked rows are valid metadata");
    assert!(matches!(
        revoked.select(selection()),
        Err(RuntimeAuthorityError::EnrollmentDenied)
    ));
}

#[test]
fn enrollment_scope_lookup_does_not_expand_exact_tuples() {
    let mut value = enrollment();
    value["installations"][0]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"workspaceId":"other","namespaceId":"other"}));
    let parsed = Enrollment::parse_json(&bytes(&value)).unwrap();
    assert!(parsed.select(selection()).is_ok());
    assert!(
        parsed
            .select(EnrollmentSelection {
                workspace_id: "other",
                namespace_id: "other",
                ..selection()
            })
            .is_ok()
    );
    assert!(matches!(
        parsed.select(EnrollmentSelection {
            workspace_id: "other",
            ..selection()
        }),
        Err(RuntimeAuthorityError::EnrollmentDenied)
    ));
    assert!(matches!(
        parsed.select(EnrollmentSelection {
            namespace_id: "other",
            ..selection()
        }),
        Err(RuntimeAuthorityError::EnrollmentDenied)
    ));
}
