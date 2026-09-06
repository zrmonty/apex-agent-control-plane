use super::support::*;
use apex_control_plane_api::{ManagedLifecycleAction as Action, ManagedLifecycleInput, proto};
use uuid::Uuid;

pub(super) fn input(f: &Fixture, action: Action) -> ManagedLifecycleInput {
    ManagedLifecycleInput {
        scope: f.input.scope.clone(),
        proxy_id: f.input.proxy_id.clone(),
        request_id: Uuid::now_v7().to_string(),
        revision_id: f.revision.revision_id.clone(),
        expected_revision_id: Some(f.revision.revision_id.clone()),
        actor_id: "operator".into(),
        reason_code: "operator_requested".into(),
        action,
        approved: true,
    }
}

#[test]
fn managed_acceptance_is_durable_not_paused_and_retry_precedes_current_generation() {
    let f = Fixture::new(false);
    let pause = input(&f, Action::Pause);
    let accepted = f
        .store
        .accept_managed_lifecycle(&pause)
        .expect("durable pause acceptance");
    assert_eq!(accepted.operation.generation, 2);
    assert_eq!(
        accepted.operation.desired_state,
        proto::ProxyDesiredState::Paused as i32
    );
    assert_eq!(
        accepted.operation.observed_state,
        proto::ProxyObservedState::Pending as i32
    );
    assert_eq!(
        accepted.proxy.lifecycle_state,
        proto::McpProxyLifecycleState::Provisioning as i32
    );
    let retire = f
        .store
        .accept_managed_lifecycle(&input(&f, Action::Retire))
        .unwrap();
    assert_eq!(retire.operation.generation, 3);
    assert_eq!(f.store.accept_managed_lifecycle(&pause).unwrap(), accepted);
    let mut conflict = pause.clone();
    conflict.reason_code = "changed_reason".into();
    let before = f.bytes();
    assert_eq!(
        f.store
            .accept_managed_lifecycle(&conflict)
            .unwrap_err()
            .code(),
        "PROXY_IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(f.bytes(), before);
}

#[test]
fn publishing_a_managed_draft_preserves_current_desired_authority() {
    use apex_control_plane_api::{ProxyStore, PublishRevision, UpdateProxyDraft};
    let f = Fixture::new(true);
    let prior_draft = f
        .store
        .get(f.input.scope.clone(), f.input.proxy_id.clone())
        .unwrap()
        .draft_revision_id;
    let draft = f
        .store
        .update_draft(UpdateProxyDraft {
            request_id: Uuid::now_v7().to_string(),
            scope: f.input.scope.clone(),
            proxy_id: f.input.proxy_id.clone(),
            expected_revision_id: prior_draft,
            actor_id: "operator".into(),
            spec: f.revision.spec.clone(),
        })
        .unwrap();
    let published = f
        .store
        .publish_revision(PublishRevision {
            request_id: Uuid::now_v7().to_string(),
            scope: f.input.scope.clone(),
            proxy_id: f.input.proxy_id.clone(),
            expected_revision_id: Some(f.revision.revision_id.clone()),
            actor_id: "operator".into(),
            draft_revision_id: draft.draft_revision_id.unwrap(),
        })
        .unwrap();
    assert_ne!(published.revision_id, f.revision.revision_id);
    assert_eq!(
        f.store
            .get(f.input.scope.clone(), f.input.proxy_id.clone())
            .unwrap()
            .active_revision_id,
        Some(f.revision.revision_id.clone())
    );
    assert_eq!(f.read().unwrap().operation, f.operation);
}

#[test]
fn all_six_actions_are_atomic_pending_and_rotation_rollback_preserve_publication() {
    use apex_control_plane_api::{PostgresProxyStore, ProxyRevisionStore, SecretRef};
    let f = Fixture::new(false);
    let before_revision = f.revision.clone();
    let deploy = f
        .store
        .accept_managed_lifecycle(&input(&f, Action::Deploy))
        .unwrap();
    assert_eq!(deploy.operation.generation, 2);
    let rotate_input = input(
        &f,
        Action::Rotate {
            secret_refs: vec![SecretRef::new("secret://rotated/current").unwrap()],
        },
    );
    let rotated = f.store.accept_managed_lifecycle(&rotate_input).unwrap();
    assert_eq!(rotated.operation.generation, 3);
    assert_ne!(
        rotated.operation.revision_id,
        f.revision.revision_id.to_string()
    );
    assert_eq!(
        f.store
            .get_revision(
                f.input.scope.clone(),
                f.input.proxy_id.clone(),
                f.revision.revision_id.clone()
            )
            .unwrap(),
        before_revision
    );
    let mut rollback = input(
        &f,
        Action::Rollback {
            target_revision_id: f.revision.revision_id.clone(),
        },
    );
    rollback.revision_id =
        apex_control_plane_api::ProxyRevisionId::new(&rotated.operation.revision_id).unwrap();
    rollback.expected_revision_id = Some(rollback.revision_id.clone());
    let restored = f.store.accept_managed_lifecycle(&rollback).unwrap();
    assert_eq!(restored.operation.generation, 4);
    assert_eq!(
        restored.operation.revision_id,
        f.revision.revision_id.to_string()
    );
    assert_eq!(
        restored.operation.observed_state,
        proto::ProxyObservedState::Pending as i32
    );
    let paused = f
        .store
        .accept_managed_lifecycle(&input(&f, Action::Pause))
        .unwrap();
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
    let mut event = f.observation();
    event.run_id = paused.operation.request_id.clone();
    event.integrity.as_mut().unwrap().event_hash =
        apex_durability::canonical_event_hash(&event).unwrap();
    f.store
        .observe_proxy_operation(
            &f.input.scope,
            &f.input.proxy_id,
            &lease,
            proto::ProxyObservedState::Paused,
            None,
            &event,
        )
        .unwrap();
    let resumed = f
        .store
        .accept_managed_lifecycle(&input(&f, Action::Resume))
        .unwrap();
    assert_eq!(resumed.operation.generation, 6);
    let retired = f
        .store
        .accept_managed_lifecycle(&input(&f, Action::Retire))
        .unwrap();
    assert_eq!(retired.operation.generation, 7);
    let restarted = PostgresProxyStore::connect(&f.database.url).unwrap();
    assert_eq!(
        restarted.accept_managed_lifecycle(&rotate_input).unwrap(),
        rotated
    );
    let row = f
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_evidence_intents WHERE proxy_id=$1",
            &[f.input.proxy_id.as_uuid()],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 8);
}

#[test]
fn rotation_rolls_back_every_mutation_when_frozen_acceptance_cannot_commit() {
    use apex_control_plane_api::SecretRef;
    let f = Fixture::new(false);
    f.client().batch_execute("CREATE FUNCTION refuse_acceptance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END; $$; CREATE TRIGGER refuse_acceptance BEFORE INSERT ON mcp_proxy_managed_acceptance FOR EACH ROW EXECUTE FUNCTION refuse_acceptance()").unwrap();
    let before = f.bytes();
    assert!(
        f.store
            .accept_managed_lifecycle(&input(
                &f,
                Action::Rotate {
                    secret_refs: vec![SecretRef::new("secret://rotated/current").unwrap()]
                }
            ))
            .is_err()
    );
    assert_eq!(f.bytes(), before);
}

#[test]
fn managed_schema_is_versioned_and_refuses_empty_or_newer_markers() {
    use apex_control_plane_api::PostgresProxyStore;
    for newer in [false, true] {
        let f = Fixture::new(false);
        let exists: bool = f
            .client()
            .query_one(
                "SELECT to_regclass('mcp_proxy_managed_schema') IS NOT NULL",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(
            exists,
            "managed allocator migration must have explicit version ownership"
        );
        if newer {
            f.client().batch_execute("ALTER TABLE mcp_proxy_managed_schema DROP CONSTRAINT mcp_proxy_managed_schema_version_check; UPDATE mcp_proxy_managed_schema SET version=2").unwrap();
        } else {
            f.client()
                .batch_execute("DELETE FROM mcp_proxy_managed_schema")
                .unwrap();
        }
        let before = f.bytes();
        assert!(PostgresProxyStore::connect(&f.database.url).is_err());
        assert_eq!(f.bytes(), before);
    }
}
