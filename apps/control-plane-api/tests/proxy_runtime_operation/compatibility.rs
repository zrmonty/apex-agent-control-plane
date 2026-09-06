use super::{managed::input, support::Fixture};
use apex_control_plane_api::{AuthBinding, ManagedLifecycleAction as Action, SecretRef, proto};

use super::support::spec;

#[test]
fn managed_metadata_preserves_authenticated_subject_and_reason_contract() {
    let f = Fixture::new(false);
    let mut action = input(&f, Action::Pause);
    action.actor_id = "a".repeat(256);
    action.reason_code = "maintenance.window".into();
    let accepted = f
        .store
        .accept_managed_lifecycle(&action)
        .expect("existing bounded metadata contract");
    assert_eq!(accepted.operation.generation, 2);
    assert_eq!(f.store.accept_managed_lifecycle(&action).unwrap(), accepted);
    action.request_id = uuid::Uuid::now_v7().to_string();
    action.reason_code = "bad\nreason".into();
    assert!(f.store.accept_managed_lifecycle(&action).is_err());
}

#[test]
fn ambiguous_rotation_cannot_cross_upstream_or_auth_binding_domains() {
    let mut spec = spec::supported_spec();
    let mut other = spec.upstreams[0].clone();
    other.upstream_id = "other".into();
    other.credential_ref = Some(SecretRef::new("secret://other/credential").unwrap());
    spec.auth_bindings.push(AuthBinding {
        binding_id: "other-binding".into(),
        inbound_subject: "other-subject".into(),
        outbound_credential_ref: other.credential_ref.clone(),
        scopes: vec!["read".into()],
    });
    spec.upstreams.push(other);
    let f = Fixture::with_spec(false, proto::ProxyDesiredState::Serving, spec);
    let before = f.bytes();
    let action = input(
        &f,
        Action::Rotate {
            secret_refs: vec![SecretRef::new("secret://new/credential").unwrap()],
        },
    );
    assert!(
        f.store.accept_managed_lifecycle(&action).is_err(),
        "flat API cannot map two old domains"
    );
    assert_eq!(f.bytes(), before);
}

#[test]
fn exact_rotation_rewrites_matching_bindings_without_populating_empty_reference_sets() {
    let mut spec = spec::supported_spec();
    let old = spec.upstreams[0].credential_ref.clone();
    spec.auth_bindings.push(AuthBinding {
        binding_id: "portfolio-binding".into(),
        inbound_subject: "unchanged-subject".into(),
        outbound_credential_ref: old,
        scopes: vec!["read".into()],
    });
    let mut other = spec.upstreams[0].clone();
    other.upstream_id = "same-domain".into();
    spec.upstreams.push(other);
    let f = Fixture::with_spec(false, proto::ProxyDesiredState::Serving, spec);
    let action = input(
        &f,
        Action::Rotate {
            secret_refs: vec![SecretRef::new("secret://new/credential").unwrap()],
        },
    );
    let accepted = f.store.accept_managed_lifecycle(&action).unwrap();
    let result = accepted.revision.spec.unwrap();
    assert_eq!(
        result.auth_bindings[0].outbound_credential_ref,
        "secret://new/credential"
    );
    assert_eq!(result.auth_bindings[0].inbound_subject, "unchanged-subject");
    assert_eq!(result.auth_bindings[0].scopes, ["read"]);
    assert_eq!(
        result.upstreams[0].credential_ref,
        "secret://new/credential"
    );
    assert!(result.upstreams[0].secret_refs.is_empty());
    assert_eq!(
        result.upstreams[1].credential_ref,
        "secret://new/credential"
    );
    assert!(result.upstreams[1].secret_refs.is_empty());
}

#[test]
fn cleanup_of_owned_history_does_not_require_current_publication_capabilities() {
    use apex_control_plane_api::{ProxyStore, UpdateProxyDraft};
    for action in [Action::Pause, Action::Retire] {
        let f = Fixture::new(false);
        let mut old_spec = spec::supported_spec();
        old_spec.ingress.protocol_revision = "2025-03-26".into();
        let draft = f
            .store
            .update_draft(UpdateProxyDraft {
                request_id: uuid::Uuid::now_v7().to_string(),
                scope: f.input.scope.clone(),
                proxy_id: f.input.proxy_id.clone(),
                expected_revision_id: f
                    .store
                    .get(f.input.scope.clone(), f.input.proxy_id.clone())
                    .unwrap()
                    .draft_revision_id,
                actor_id: "operator".into(),
                spec: old_spec,
            })
            .unwrap()
            .draft_revision_id
            .unwrap();
        // Seed historical publication, as an earlier policy version would have done.
        // No guards disabled, no published bytes modified, only this fixture's schema.
        f.execute(
            "UPDATE mcp_proxy_revisions SET is_published=TRUE WHERE proxy_id=$1 AND revision_id=$2",
            &[f.input.proxy_id.as_uuid(), draft.as_uuid()],
        );
        let mut submission = f.input.clone();
        submission.request_id = uuid::Uuid::now_v7().to_string();
        submission.expected_generation = 1;
        submission.revision_id = draft.clone();
        submission.evidence.event_id = uuid::Uuid::now_v7().to_string();
        submission.evidence.run_id = submission.request_id.clone();
        submission.evidence.integrity.as_mut().unwrap().event_hash =
            apex_durability::canonical_event_hash(&submission.evidence).unwrap();
        f.store.submit_proxy_operation(&submission).unwrap();
        let mut cleanup = input(&f, action);
        cleanup.revision_id = draft.clone();
        cleanup.expected_revision_id = Some(draft);
        assert_eq!(
            f.store
                .accept_managed_lifecycle(&cleanup)
                .expect("cleanup of owned history")
                .operation
                .generation,
            3
        );
        let lease = f
            .store
            .lease_proxy_operation(
                &f.input.scope,
                &f.input.proxy_id,
                "controller-a",
                std::time::Duration::from_secs(30),
            )
            .unwrap()
            .unwrap();
        let target = proto::RuntimeTarget {
            workspace_id: f.input.scope.workspace_id.clone(),
            namespace_id: f.input.scope.namespace_id.clone(),
            proxy_id: f.input.proxy_id.to_string(),
            revision_id: cleanup.revision_id.to_string(),
            generation: 3,
            fencing_token: lease.fencing_token,
        };
        f.store
            .read_current_runtime_operation(&target, &lease.operation.operation_id, "controller-a")
            .expect("cleanup callback of owned history");
    }
}

#[test]
fn legacy_validation_cannot_change_managed_desired_state_or_published_history() {
    use apex_control_plane_api::LifecycleCommand;
    use apex_control_plane_api::{ProxyLifecycleStore, TransitionProxyLifecycle};
    let f = Fixture::new(false);
    let before = f.bytes();
    let result = f.store.transition(TransitionProxyLifecycle {
        request_id: uuid::Uuid::now_v7().to_string(),
        scope: f.input.scope.clone(),
        proxy_id: f.input.proxy_id.clone(),
        revision_id: f.revision.revision_id.clone(),
        expected_revision_id: Some(f.revision.revision_id.clone()),
        actor_id: "operator".into(),
        reason_code: "proxy.validation_started".into(),
        command: LifecycleCommand::Validate,
        approved: false,
    });
    assert!(
        result.is_err(),
        "legacy state transition must refuse managed desired authority"
    );
    assert_eq!(f.bytes(), before);
}

#[test]
fn legacy_retirement_cannot_bypass_managed_cleanup_evidence() {
    use apex_control_plane_api::{ProxyRevisionStore, RetireProxy};
    let f = Fixture::new(false);
    let before = f.bytes();
    let result = f.store.retire(RetireProxy {
        request_id: uuid::Uuid::now_v7().to_string(),
        scope: f.input.scope.clone(),
        proxy_id: f.input.proxy_id.clone(),
        expected_revision_id: Some(f.revision.revision_id.clone()),
    });
    assert!(
        result.is_err(),
        "legacy retirement cannot assert physical cleanup"
    );
    assert_eq!(f.bytes(), before);
}
