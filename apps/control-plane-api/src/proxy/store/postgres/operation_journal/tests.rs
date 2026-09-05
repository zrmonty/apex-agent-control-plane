use super::*;
use apex_durability::{canonical_event_hash, proto as evidence};
use prost_types::{Struct, Value, value::Kind};
use std::time::Duration;

#[path = "tests_completion.rs"]
mod completion;
#[path = "tests_schema.rs"]
mod schema;
#[path = "tests_target.rs"]
mod target;

fn scope() -> ExactScope {
    ExactScope {
        workspace_id: "workspace".into(),
        namespace_id: "namespace".into(),
    }
}

fn proxy() -> ProxyId {
    ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84").unwrap()
}

fn envelope() -> evidence::EventEnvelope {
    let mut event = evidence::EventEnvelope {
        event_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86".into(),
        timestamp: "2024-05-03T12:34:56.123456Z".into(),
        r#type: 7,
        agent_id: "apex-control-gateway".into(),
        run_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e87".into(),
        parent_run_id: None,
        trace_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e87".into(),
        scope: Some(evidence::Scope {
            workspace_id: "workspace".into(),
            namespace_id: "namespace".into(),
            agent_group_ids: vec![],
        }),
        actor: Some(evidence::Actor {
            r#type: 3,
            id: "apex-control-plane".into(),
        }),
        version: Some(evidence::Version {
            agent_code: "apex-control-gateway".into(),
            prompt: "proxy-lifecycle-v1".into(),
            model: "n-a".into(),
        }),
        data: Some(Struct {
            fields: [(
                "proxy_id".into(),
                Value {
                    kind: Some(Kind::StringValue(proxy().to_string())),
                },
            )]
            .into_iter()
            .collect(),
        }),
        integrity: Some(evidence::Integrity {
            prev_hash: None,
            event_hash: String::new(),
        }),
        schema_version: 1,
    };
    event.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&event).unwrap();
    event
}

#[test]
fn evidence_intent_preserves_original_identity_time_hash_and_payload() {
    let event = envelope();
    let scope = scope();
    let proxy = proxy();
    let intent = EvidenceIntent::new(
        Target {
            scope: &scope,
            proxy_id: &proxy,
        },
        &event,
    )
    .unwrap();
    let decoded = evidence::EventEnvelope::decode(intent.envelope.as_slice()).unwrap();
    assert_eq!(intent.event_id.to_string(), event.event_id);
    assert_eq!(intent.event_timestamp, "2024-05-03T12:34:56.123456Z");
    assert_eq!(
        intent.payload_hash,
        event.integrity.as_ref().unwrap().event_hash
    );
    assert_eq!(decoded, event);
}

#[test]
fn evidence_intent_rejects_another_proxy_even_in_the_same_scope() {
    let scope = scope();
    let other = ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e88").unwrap();
    let result = EvidenceIntent::new(
        Target {
            scope: &scope,
            proxy_id: &other,
        },
        &envelope(),
    );
    assert_eq!(result.unwrap_err().code(), "INVALID_PROXY_SCOPE");
}

// These tests intentionally fail if the dedicated database is not configured.
// Each test owns an uncommitted schema; rollback removes its fixtures and DDL.
fn database() -> apex_durability::PostgresConnection {
    let url = std::env::var("APEX_PROXY_JOURNAL_TEST_DATABASE_URL")
        .expect("set APEX_PROXY_JOURNAL_TEST_DATABASE_URL to a disposable PostgreSQL database");
    apex_durability::PostgresConnection::Standard(
        postgres::Client::connect(&url, postgres::NoTls).expect("dedicated PostgreSQL unavailable"),
    )
}

fn fixture(tx: &mut Transaction<'_>) -> ProxyRevisionId {
    let schema = format!("journal_test_{}", Uuid::now_v7().simple());
    tx.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();
    tx.query_one("SELECT set_config('search_path', $1, true)", &[&schema])
        .unwrap();
    tx.batch_execute(include_str!(
        "../../../../../../../deploy/postgres/mcp_proxies.sql"
    ))
    .unwrap();
    tx.batch_execute(include_str!(
        "../../../../../../../deploy/postgres/mcp_proxy_operations.sql"
    ))
    .unwrap();
    let revision = ProxyRevisionId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85").unwrap();
    tx.execute(
        "INSERT INTO mcp_proxies (proxy_id, workspace_id, namespace_id, display_name,
        slug, lifecycle_state, redaction_status, active_revision_id, created_at_micros,
        desired_state) VALUES ($1, 'workspace', 'namespace', 'Test', 'test', 'draft',
        'redacted', $2, 0, 'draft')",
        &[proxy().as_uuid(), revision.as_uuid()],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO mcp_proxy_revisions (proxy_id, revision_id, spec_json, config_hash,
        lifecycle_state, redaction_status, created_by, created_at_micros, created_at, is_published)
        VALUES ($1, $2, '{}', $3, 'draft', 'redacted', 'operator', 0,
        '2024-05-03T12:34:56.123456Z', TRUE)",
        &[proxy().as_uuid(), revision.as_uuid(), &"0".repeat(64)],
    )
    .unwrap();
    revision
}

fn submission<'a>(
    target: Target<'a>,
    revision: &'a ProxyRevisionId,
    evidence: &'a evidence::EventEnvelope,
) -> SubmitOperation<'a> {
    SubmitOperation {
        target,
        request_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e87",
        expected_revision_id: Some(revision),
        revision_id: revision,
        expected_generation: 0,
        desired_state: ProxyDesiredState::Serving,
        evidence,
    }
}

#[test]
fn committed_submission_replays_the_original_acceptance_and_evidence() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let input = submission(target, &revision, &event);
    let accepted = submit_operation(&mut tx, &input).unwrap();
    assert_eq!(accepted.generation, 1);
    assert_eq!(accepted.observed_state, ProxyObservedState::Pending as i32);
    assert_ne!(accepted.operation_id, accepted.request_id);
    let pending = pending_evidence_intents(&mut tx, target, 10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].intent.event_timestamp, event.timestamp);
    assert_eq!(submit_operation(&mut tx, &input).unwrap(), accepted);
    let mut regenerated = event.clone();
    regenerated.event_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e90".into();
    regenerated.timestamp = "2024-05-03T12:34:57.999999Z".into();
    regenerated.integrity.as_mut().unwrap().event_hash =
        canonical_event_hash(&regenerated).unwrap();
    assert_eq!(
        submit_operation(&mut tx, &submission(target, &revision, &regenerated)).unwrap(),
        accepted
    );
    assert_eq!(
        pending_evidence_intents(&mut tx, target, 10).unwrap(),
        pending
    );
    let desired = tx
        .query_one(
            "SELECT desired_state, deployment_generation FROM mcp_proxies
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3",
            &[&scope.workspace_id, &scope.namespace_id, proxy.as_uuid()],
        )
        .unwrap();
    assert_eq!(desired.get::<_, String>(0), "serving");
    assert_eq!(desired.get::<_, i64>(1), 1);
}

#[test]
fn reused_request_with_different_body_and_stale_generation_are_refused() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let mut input = submission(target, &revision, &event);
    submit_operation(&mut tx, &input).unwrap();
    input.desired_state = ProxyDesiredState::Paused;
    assert_eq!(
        submit_operation(&mut tx, &input).unwrap_err().code(),
        "PROXY_IDEMPOTENCY_CONFLICT"
    );
    input.request_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e89";
    let mut next_event = event.clone();
    next_event.event_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e90".into();
    next_event.run_id = input.request_id.into();
    next_event.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&next_event).unwrap();
    input.evidence = &next_event;
    assert_eq!(
        submit_operation(&mut tx, &input).unwrap_err().code(),
        "PROXY_REVISION_CONFLICT"
    );
    assert_eq!(
        pending_evidence_intents(&mut tx, target, 10).unwrap().len(),
        1
    );
}

#[test]
fn enclosing_transaction_rollback_removes_operation_and_intent_together() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let mut savepoint = tx.transaction().unwrap();
    let result = submit_operation(&mut savepoint, &submission(target, &revision, &event)).unwrap();
    savepoint.rollback().unwrap();
    assert!(
        get_operation(&mut tx, target, &result.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        pending_evidence_intents(&mut tx, target, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn lease_handoff_fences_old_observers_and_observation_replays_one_intent() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let input = submission(target, &revision, &event);
    let accepted = submit_operation(&mut tx, &input).unwrap();
    let first = lease_operation(
        &mut tx,
        target,
        "worker_one",
        std::time::Duration::from_secs(30),
    )
    .unwrap()
    .unwrap();
    assert!(
        lease_operation(
            &mut tx,
            target,
            "worker_two",
            std::time::Duration::from_secs(30)
        )
        .unwrap()
        .is_none()
    );
    // Emulate a crashed owner's expired lease without a wall-clock sleep.
    tx.execute(
        "UPDATE mcp_proxy_controller_leases SET expires_at_micros = 0
        WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3",
        &[&scope.workspace_id, &scope.namespace_id, proxy.as_uuid()],
    )
    .unwrap();
    let second = lease_operation(
        &mut tx,
        target,
        "worker_two",
        std::time::Duration::from_secs(30),
    )
    .unwrap()
    .unwrap();
    assert!(second.fencing_token > first.fencing_token);
    let mut observed_event = event.clone();
    observed_event.event_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e90".into();
    observed_event.integrity.as_mut().unwrap().event_hash =
        canonical_event_hash(&observed_event).unwrap();
    assert_eq!(
        observe_operation(
            &mut tx,
            target,
            &first,
            ProxyObservedState::Ready,
            None,
            &observed_event
        )
        .unwrap_err()
        .code(),
        "PROXY_STALE_FENCE"
    );
    let observed = observe_operation(
        &mut tx,
        target,
        &second,
        ProxyObservedState::Ready,
        None,
        &observed_event,
    )
    .unwrap();
    assert_eq!(
        observe_operation(
            &mut tx,
            target,
            &second,
            ProxyObservedState::Ready,
            None,
            &observed_event
        )
        .unwrap(),
        observed
    );
    let mut conflicting = observed_event.clone();
    conflicting.timestamp = "2024-05-03T12:34:57.999999Z".into();
    conflicting.integrity.as_mut().unwrap().event_hash =
        canonical_event_hash(&conflicting).unwrap();
    assert_eq!(
        observe_operation(
            &mut tx,
            target,
            &second,
            ProxyObservedState::Ready,
            None,
            &conflicting
        )
        .unwrap_err()
        .code(),
        "PROXY_IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(submit_operation(&mut tx, &input).unwrap(), accepted);
    assert_eq!(
        get_operation(&mut tx, target, &accepted.operation_id).unwrap(),
        Some(observed)
    );
    assert_eq!(
        pending_evidence_intents(&mut tx, target, 10).unwrap().len(),
        2
    );
}

#[test]
fn relay_acknowledgement_cannot_mark_another_scope_or_change_original_evidence() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let result = submit_operation(&mut tx, &submission(target, &revision, &event)).unwrap();
    let hash = &event.integrity.as_ref().unwrap().event_hash;
    let foreign = ExactScope {
        workspace_id: "other".into(),
        namespace_id: "namespace".into(),
    };
    let foreign_target = Target {
        scope: &foreign,
        proxy_id: &proxy,
    };
    assert!(
        !mark_evidence_enqueued(
            &mut tx,
            foreign_target,
            &result.operation_id,
            &event.event_id,
            hash
        )
        .unwrap()
    );
    assert!(
        mark_evidence_enqueued(&mut tx, target, &result.operation_id, &event.event_id, hash)
            .unwrap()
    );
    assert!(
        !mark_evidence_enqueued(&mut tx, target, &result.operation_id, &event.event_id, hash)
            .unwrap()
    );
    assert!(
        pending_evidence_intents(&mut tx, target, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn submission_rejects_noncanonical_request_ids_and_foreign_scope() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let mut input = submission(target, &revision, &event);
    for invalid in [
        "018F3D4A-8B9C-7D0E-8F12-3A4B5C6D7E87",
        "018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e87",
    ] {
        input.request_id = invalid;
        assert_eq!(
            submit_operation(&mut tx, &input).unwrap_err().code(),
            "INVALID_PROXY_REQUEST_ID"
        );
    }
    let foreign_scope = ExactScope {
        workspace_id: "other".into(),
        namespace_id: "namespace".into(),
    };
    let mut foreign_event = event.clone();
    foreign_event.scope.as_mut().unwrap().workspace_id = "other".into();
    foreign_event.integrity.as_mut().unwrap().event_hash =
        canonical_event_hash(&foreign_event).unwrap();
    let foreign_target = Target {
        scope: &foreign_scope,
        proxy_id: &proxy,
    };
    assert_eq!(
        submit_operation(
            &mut tx,
            &submission(foreign_target, &revision, &foreign_event)
        )
        .unwrap_err()
        .code(),
        "PROXY_NOT_FOUND"
    );
    assert!(
        pending_evidence_intents(&mut tx, target, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn terminal_observations_must_match_the_persisted_desired_state() {
    use ProxyDesiredState::{Paused as WantPaused, Retired as WantRetired, Serving};
    use ProxyObservedState::{Failed, NotServing, Paused, Ready, Reconciling, Retired};
    let cases = [
        (Serving, Ready, true),
        (Serving, Paused, false),
        (Serving, Retired, false),
        (WantPaused, Ready, false),
        (WantPaused, Paused, true),
        (WantPaused, Retired, false),
        (WantRetired, Ready, false),
        (WantRetired, Paused, false),
        (WantRetired, Retired, true),
        (Serving, Reconciling, true),
        (Serving, Failed, true),
        (Serving, NotServing, true),
        (WantPaused, Reconciling, true),
        (WantPaused, Failed, true),
        (WantPaused, NotServing, true),
        (WantRetired, Reconciling, true),
        (WantRetired, Failed, true),
        (WantRetired, NotServing, true),
    ];
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    for (desired, observed, compatible) in cases {
        let mut case = tx.transaction().unwrap();
        let mut input = submission(target, &revision, &event);
        input.desired_state = desired;
        let accepted = submit_operation(&mut case, &input).unwrap();
        let mut lease = lease_operation(
            &mut case,
            target,
            "worker",
            std::time::Duration::from_secs(30),
        )
        .unwrap()
        .unwrap();
        // A caller-modified lease snapshot cannot change durable desired state.
        lease.operation.desired_state = match observed {
            Ready => Serving,
            Paused => WantPaused,
            Retired => WantRetired,
            _ => desired,
        } as i32;
        let mut observed_event = event.clone();
        observed_event.event_id = Uuid::now_v7().to_string();
        observed_event.integrity.as_mut().unwrap().event_hash =
            canonical_event_hash(&observed_event).unwrap();
        let result = observe_operation(&mut case, target, &lease, observed, None, &observed_event);
        if compatible {
            let result = result.unwrap();
            assert_eq!(result.desired_state, desired as i32);
            assert_eq!(result.observed_state, observed as i32);
            assert_eq!(
                pending_evidence_intents(&mut case, target, 10)
                    .unwrap()
                    .len(),
                2
            );
        } else {
            assert_eq!(
                result.unwrap_err().code(),
                "INVALID_PROXY_LIFECYCLE_TRANSITION",
                "{desired:?} must not complete as {observed:?}"
            );
            assert_eq!(
                get_operation(&mut case, target, &accepted.operation_id).unwrap(),
                Some(accepted)
            );
            assert_eq!(
                pending_evidence_intents(&mut case, target, 10)
                    .unwrap()
                    .len(),
                1
            );
            let mut tamper = case.transaction().unwrap();
            let error = tamper
                .execute(
                    "UPDATE mcp_proxy_operations SET observed_state = $4
                 WHERE workspace_id = $1 AND namespace_id = $2 AND proxy_id = $3",
                    &[
                        &scope.workspace_id,
                        &scope.namespace_id,
                        proxy.as_uuid(),
                        &(observed as i32),
                    ],
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                Some(&postgres::error::SqlState::CHECK_VIOLATION)
            );
            tamper.rollback().unwrap();
        }
        case.rollback().unwrap();
    }
}
