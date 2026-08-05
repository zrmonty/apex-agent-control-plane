#![cfg(all(test, feature = "postgres"))]

use super::postgres::PostgresOutbox;
use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{IngestRequest, proto};
use prost::Message;

fn url() -> Option<String> {
    std::env::var("APEX_POSTGRES_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

fn valid_outbox_event(event_id: &str) -> IngestRequest {
    // pending() re-validates stored protobuf envelopes; raw bytes are skipped.
    let mut envelope = proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2024-02-29T23:59:59.000000Z".to_owned(),
        r#type: 1,
        agent_id: "agent".to_owned(),
        run_id: "run".to_owned(),
        parent_run_id: None,
        trace_id: "trace".to_owned(),
        scope: Some(proto::Scope {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_group_ids: vec![],
        }),
        actor: Some(proto::Actor {
            r#type: 2,
            id: "agent".to_owned(),
        }),
        version: Some(proto::Version {
            agent_code: "code".to_owned(),
            prompt: "prompt".to_owned(),
            model: "model".to_owned(),
        }),
        data: Some(prost_types::Struct::default()),
        integrity: Some(proto::Integrity {
            prev_hash: None,
            event_hash: String::new(),
        }),
        schema_version: 1,
    };
    let hash = IngestRequest::canonical_hash_for_test(&envelope).unwrap();
    envelope.integrity.as_mut().unwrap().event_hash = hash;
    IngestRequest::new(
        event_id,
        "acme",
        "prod",
        envelope.encode_to_vec(),
    )
}

#[test]
fn postgres_outbox_enqueue_complete_and_replay() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    let event_id = "018f5c91-2d88-7c00-8000-0000000000e2";
    let event = valid_outbox_event(event_id);
    let _ = outbox.enqueue(&event);
    match outbox.enqueue(&event).unwrap() {
        EnqueueResult::Enqueued | EnqueueResult::AlreadyPending => {}
        EnqueueResult::AlreadyComplete => return,
    }
    let pending = outbox.pending();
    assert!(
        pending.iter().any(|e| e.event_id == event_id),
        "pending replay must include enqueued validated envelopes"
    );
    outbox
        .mark_complete(&OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event_id.into(),
        })
        .unwrap();
    assert_eq!(
        outbox.enqueue(&event).unwrap(),
        EnqueueResult::AlreadyComplete
    );
}

#[test]
fn postgres_outbox_connect_rejects_invalid_capacity_and_connection_string() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    assert!(PostgresOutbox::connect(&url, 0).is_err());
    assert!(PostgresOutbox::connect(&url, 1_000_001).is_err());
    assert!(PostgresOutbox::connect("", 64).is_err());
    assert!(PostgresOutbox::connect(&"x".repeat(2049), 64).is_err());
}

#[test]
fn postgres_outbox_enqueue_rejects_invalid_identifiers_and_envelopes() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    let mut event = valid_outbox_event("018f5c91-2d88-7c00-8000-0000000000e3");
    event.workspace_id = "bad workspace".into();
    assert!(outbox.enqueue(&event).is_err());

    let mut bad_id_event = valid_outbox_event("not-a-uuid");
    bad_id_event.event_id = "not-a-uuid".into();
    assert!(outbox.enqueue(&bad_id_event).is_err());

    let mut empty_envelope = valid_outbox_event("018f5c91-2d88-7c00-8000-0000000000e4");
    empty_envelope.envelope = Vec::new();
    assert_eq!(
        outbox.enqueue(&empty_envelope).unwrap_err().code,
        crate::GatewayErrorCode::InvalidEnvelope
    );
}

#[test]
fn postgres_outbox_conflicting_pending_envelope_is_rejected() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    let event_id = "018f5c91-2d88-7c00-8000-0000000000e5";
    let event = valid_outbox_event(event_id);
    let first = outbox.enqueue(&event).unwrap();
    if matches!(first, EnqueueResult::AlreadyComplete) {
        eprintln!("skip: key already committed from a prior run");
        return;
    }
    let mut different = valid_outbox_event(event_id);
    different.envelope = valid_outbox_event("018f5c91-2d88-7c00-8000-0000000000e6").envelope;
    let error = outbox.enqueue(&different).unwrap_err();
    assert_eq!(error.code, crate::GatewayErrorCode::IdempotencyConflict);
}

#[test]
fn postgres_outbox_mark_complete_rejects_invalid_key_and_missing_row() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    assert!(
        outbox
            .mark_complete(&OutboxKey {
                workspace_id: "bad workspace".into(),
                namespace_id: "prod".into(),
                event_id: "018f5c91-2d88-7c00-8000-0000000000e7".into(),
            })
            .is_err()
    );
    // A syntactically valid key for a row that was never enqueued is an
    // internal error, not a silent no-op.
    assert!(
        outbox
            .mark_complete(&OutboxKey {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
                event_id: "018f5c91-2d88-7c00-8000-0000000000e8".into(),
            })
            .is_err()
    );
}

#[test]
fn postgres_outbox_mark_complete_on_already_complete_row_is_a_no_op() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    let event_id = "018f5c91-2d88-7c00-8000-0000000000e9";
    let event = valid_outbox_event(event_id);
    let _ = outbox.enqueue(&event);
    let key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event_id.into(),
    };
    let _ = outbox.mark_complete(&key);
    // Already complete: the second call finds zero rows updated but the row
    // does exist, so it must still succeed rather than error.
    outbox.mark_complete(&key).unwrap();
}
