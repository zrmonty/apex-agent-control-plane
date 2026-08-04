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
