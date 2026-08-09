use super::*;
use crate::{EventPublisher, GatewayError, IngestRequest, proto};
use prost::Message;
use std::fs::{create_dir, remove_dir_all, write};

#[derive(Default)]
struct CountingPublisher(usize);

impl EventPublisher for CountingPublisher {
    fn publish(
        &mut self,
        _event: &IngestRequest,
    ) -> Result<crate::PublishOutcome, GatewayError> {
        self.0 += 1;
        Ok(crate::PublishOutcome::Published)
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
fn completed_outbox_retains_payload_for_delivery_reconciliation() {
    let mut outbox = InMemoryOutbox::new(4).unwrap();
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000010");
    let key = OutboxKey {
        workspace_id: event.workspace_id.clone(),
        namespace_id: event.namespace_id.clone(),
        event_id: event.event_id.clone(),
    };
    outbox.enqueue(&event).unwrap();
    outbox.mark_complete(&key).unwrap();
    assert_eq!(
        outbox.recent_completed_batch(0, 4).unwrap(),
        vec![event],
        "completed payloads must remain reconstructable for a missing inbox repair"
    );
}

#[test]
fn a_quarantined_outbox_row_is_not_replayed_after_restart() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-quarantine-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000010");
    let key = OutboxKey {
        workspace_id: event.workspace_id.clone(),
        namespace_id: event.namespace_id.clone(),
        event_id: event.event_id.clone(),
    };
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        outbox.enqueue(&event).unwrap();
        outbox.quarantine(&[key], "test_poison").unwrap();
        assert!(outbox.pending_batch(4).unwrap().is_empty());
    }
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert!(reopened.pending_batch(4).unwrap().is_empty());
    assert_eq!(reopened.enqueue(&event).unwrap(), EnqueueResult::AlreadyPending);
    remove_dir_all(base).unwrap();
}

#[test]
fn quarantined_file_row_can_be_explicitly_requeued_after_restart() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-requeue-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000011");
    let key = OutboxKey {
        workspace_id: event.workspace_id.clone(),
        namespace_id: event.namespace_id.clone(),
        event_id: event.event_id.clone(),
    };
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        outbox.enqueue(&event).unwrap();
        outbox.quarantine(std::slice::from_ref(&key), "test_poison").unwrap();
    }
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(reopened.quarantined_batch(4).unwrap(), vec![key.clone()]);
    reopened
        .requeue_quarantined(std::slice::from_ref(&key))
        .unwrap();
    assert_eq!(reopened.pending_batch(4).unwrap(), vec![event]);
    drop(reopened);
    let mut final_open = FileOutbox::open(&path, &base, 4).unwrap();
    assert!(final_open.quarantined_batch(4).unwrap().is_empty());
    assert_eq!(final_open.pending_batch(4).unwrap().len(), 1);
    remove_dir_all(base).unwrap();
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
fn file_outbox_settles_a_published_batch_in_one_journal_operation() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-batch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let first = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    let second = sample_event("018f5c91-2d88-7c00-8000-000000000003");
    let keys = [first.event_id.as_str(), second.event_id.as_str()]
        .into_iter()
        .map(|event_id| OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event_id.into(),
        })
        .collect::<Vec<_>>();
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        outbox.enqueue(&first).unwrap();
        outbox.enqueue(&second).unwrap();
        outbox.mark_complete_many(&keys).unwrap();
        assert!(outbox.pending().is_empty());
    }
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(reopened.enqueue(&first).unwrap(), EnqueueResult::AlreadyComplete);
    assert_eq!(reopened.enqueue(&second).unwrap(), EnqueueResult::AlreadyComplete);
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

