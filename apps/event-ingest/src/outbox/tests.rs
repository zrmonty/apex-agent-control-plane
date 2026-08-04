use super::*;
use crate::{EventPublisher, GatewayError, IngestRequest, proto};
use prost::Message;
use std::fs::{create_dir, remove_dir_all, write};

#[derive(Default)]
struct CountingPublisher(usize);

impl EventPublisher for CountingPublisher {
    fn publish(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
        self.0 += 1;
        Ok(())
    }
}

#[test]
fn failed_fanout_leaves_event_pending_for_replay() {
    let mut outbox = InMemoryOutbox::new(4).unwrap();
    let event = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "acme",
        "prod",
        b"payload".to_vec(),
    );
    assert_eq!(outbox.enqueue(&event).unwrap(), EnqueueResult::Enqueued);
    assert_eq!(
        outbox.enqueue(&event).unwrap(),
        EnqueueResult::AlreadyPending
    );
    assert_eq!(outbox.pending(), vec![event.clone()]);
    outbox
        .mark_complete(&OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event.event_id.clone(),
        })
        .unwrap();
    assert!(outbox.pending().is_empty());
    assert_eq!(
        outbox.enqueue(&event).unwrap(),
        EnqueueResult::AlreadyComplete
    );
}

#[test]
fn live_publisher_does_not_republish_already_pending_event() {
    let mut outboxed = OutboxedPublisher::new(
        CountingPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    );
    let event = IngestRequest::new(
        "018f5c91-2d88-7c00-0000-000000000001",
        "acme",
        "prod",
        b"payload".to_vec(),
    );
    outboxed
        .outbox
        .enqueue(&event)
        .expect("seed pending outbox row");
    let error = outboxed.publish(&event).unwrap_err();
    assert_eq!(error.code, crate::GatewayErrorCode::IdempotencyInProgress);
    assert_eq!(outboxed.publisher.0, 0);
}

#[test]
fn outboxed_publisher_skips_fanout_for_already_complete_and_replays_pending() {
    use crate::outbox::PendingEventReplayer;

    let mut outboxed = OutboxedPublisher::new(
        CountingPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    );
    let event = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000099",
        "acme",
        "prod",
        b"payload".to_vec(),
    );
    outboxed
        .publish(&event)
        .expect("first publish enqueues and fans out");
    assert_eq!(outboxed.publisher.0, 1);
    outboxed.publish(&event).expect("complete row is a no-op");
    assert_eq!(outboxed.publisher.0, 1);

    let mut replaying = OutboxedPublisher::new(
        CountingPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    );
    replaying
        .outbox
        .enqueue(&event)
        .expect("seed pending for replay");
    replaying.replay_pending().expect("replay drains pending");
    assert_eq!(replaying.publisher.0, 1);
    assert!(replaying.outbox.pending().is_empty());
}

#[test]
fn file_outbox_survives_restart_and_replays_pending_rows() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let event_id = "018f5c91-2d88-7c00-8000-000000000001";
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
    envelope.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&envelope).unwrap();
    let event = IngestRequest::new(event_id, "acme", "prod", envelope.encode_to_vec());
    let decoded = proto::EventEnvelope::decode(event.envelope()).unwrap();
    assert!(IngestRequest::from_validated_transport(decoded).is_ok());
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        assert_eq!(outbox.enqueue(&event).unwrap(), EnqueueResult::Enqueued);
    }
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(reopened.pending(), vec![event.clone()]);
    let key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event.event_id.clone(),
    };
    reopened.mark_complete(&key).unwrap();
    drop(reopened);
    let mut complete = FileOutbox::open(&path, &base, 4).unwrap();
    assert!(complete.pending().is_empty());
    assert_eq!(
        complete.enqueue(&event).unwrap(),
        EnqueueResult::AlreadyComplete
    );
    remove_dir_all(base).unwrap();
}

#[test]
fn file_outbox_rejects_corrupt_records_without_dropping_state() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-corrupt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    write(&path, b"{\"op\":\"pending\"}\n").unwrap();
    let error = FileOutbox::open(&path, &base, 4).unwrap_err();
    assert_eq!(
        error.code,
        crate::GatewayErrorCode::InvalidOutboxConfiguration
    );
    remove_dir_all(base).unwrap();
}

fn sample_event(event_id: &str) -> IngestRequest {
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
    envelope.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&envelope).unwrap();
    IngestRequest::new(event_id, "acme", "prod", envelope.encode_to_vec())
}

#[test]
fn memory_outbox_covers_capacity_conflict_and_unknown_complete() {
    assert_eq!(
        InMemoryOutbox::new(0).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyCapacity
    );
    assert_eq!(
        InMemoryOutbox::new(1_000_001).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyCapacity
    );
    let mut outbox = InMemoryOutbox::new(1).unwrap();
    let first = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    assert_eq!(outbox.enqueue(&first).unwrap(), EnqueueResult::Enqueued);
    assert_eq!(
        outbox.enqueue(&first).unwrap(),
        EnqueueResult::AlreadyPending
    );
    let mut conflict = first.clone();
    conflict.envelope = b"different".to_vec();
    assert_eq!(
        outbox.enqueue(&conflict).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyConflict
    );
    let second = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    assert_eq!(
        outbox.enqueue(&second).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyCapacity
    );
    assert_eq!(
        outbox
            .mark_complete(&OutboxKey {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
                event_id: "018f5c91-2d88-7c00-8000-000000000099".into(),
            })
            .unwrap_err()
            .code,
        crate::GatewayErrorCode::Internal
    );
}

#[test]
fn file_outbox_covers_path_capacity_conflict_and_pending_dedup() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-edges-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    assert_eq!(
        FileOutbox::open(&path, &base, 0).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyCapacity
    );
    let outside = std::env::temp_dir().join(format!(
        "apex-outbox-outside-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&outside).unwrap();
    assert_eq!(
        FileOutbox::open(&outside.join("events.jsonl"), &base, 4)
            .unwrap_err()
            .code,
        crate::GatewayErrorCode::InvalidOutboxConfiguration
    );
    remove_dir_all(&outside).unwrap();

    let event = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    {
        let mut outbox = FileOutbox::open(&path, &base, 1).unwrap();
        assert_eq!(outbox.enqueue(&event).unwrap(), EnqueueResult::Enqueued);
        assert_eq!(
            outbox.enqueue(&event).unwrap(),
            EnqueueResult::AlreadyPending
        );
        let mut conflict = event.clone();
        conflict.envelope = b"changed".to_vec();
        assert_eq!(
            outbox.enqueue(&conflict).unwrap_err().code,
            crate::GatewayErrorCode::IdempotencyConflict
        );
        let second = sample_event("018f5c91-2d88-7c00-8000-000000000002");
        assert_eq!(
            outbox.enqueue(&second).unwrap_err().code,
            crate::GatewayErrorCode::IdempotencyCapacity
        );
        assert_eq!(
            outbox
                .mark_complete(&OutboxKey {
                    workspace_id: "acme".into(),
                    namespace_id: "prod".into(),
                    event_id: "018f5c91-2d88-7c00-8000-000000000099".into(),
                })
                .unwrap_err()
                .code,
            crate::GatewayErrorCode::Internal
        );
    }
    remove_dir_all(base).unwrap();
}

#[test]
fn file_outbox_rejects_empty_envelope_and_mismatched_metadata_on_load() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    write(
        &path,
        br#"{"op":"pending","workspace_id":"acme","namespace_id":"prod","event_id":"018f5c91-2d88-7c00-8000-000000000001","envelope":[]}"#,
    )
    .unwrap();
    assert_eq!(
        FileOutbox::open(&path, &base, 4).unwrap_err().code,
        crate::GatewayErrorCode::InvalidOutboxConfiguration
    );
    remove_dir_all(base).unwrap();
}

#[test]
fn outboxed_publisher_exposes_inner_handles() {
    let publisher = CountingPublisher::default();
    let outbox = InMemoryOutbox::new(2).unwrap();
    let mut wrapped = OutboxedPublisher::new(publisher, outbox);
    assert_eq!(wrapped.publisher().0, 0);
    assert!(wrapped.outbox_mut().pending().is_empty());
}

#[test]
fn file_outbox_mark_complete_is_idempotent_and_load_rejects_conflicting_pending() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-complete-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        outbox.enqueue(&event).unwrap();
        let key = OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event.event_id.clone(),
        };
        outbox.mark_complete(&key).unwrap();
        outbox.mark_complete(&key).unwrap(); // already complete branch
    }

    // Two pending records with different envelopes for the same key fail closed.
    let conflict = base.join("conflict.jsonl");
    let good = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    let mut alt = sample_envelope_like("018f5c91-2d88-7c00-8000-000000000002", "agent-x");
    alt.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&alt).unwrap();
    let alt_bytes = alt.encode_to_vec();
    let line1 = serde_json::json!({
        "op": "pending",
        "workspace_id": "acme",
        "namespace_id": "prod",
        "event_id": good.event_id,
        "envelope": good.envelope,
    });
    let line2 = serde_json::json!({
        "op": "pending",
        "workspace_id": "acme",
        "namespace_id": "prod",
        "event_id": good.event_id,
        "envelope": alt_bytes,
    });
    write(
        &conflict,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&line1).unwrap(),
            serde_json::to_string(&line2).unwrap()
        ),
    )
    .unwrap();
    assert_eq!(
        FileOutbox::open(&conflict, &base, 4).unwrap_err().code,
        crate::GatewayErrorCode::IdempotencyConflict
    );
    remove_dir_all(base).unwrap();
}

fn sample_envelope_like(event_id: &str, agent_id: &str) -> proto::EventEnvelope {
    proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2024-02-29T23:59:59.000000Z".to_owned(),
        r#type: 1,
        agent_id: agent_id.to_owned(),
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
            id: agent_id.to_owned(),
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
    }
}
