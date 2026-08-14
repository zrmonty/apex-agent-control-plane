use super::*;
use crate::{EventPublisher, GatewayError, IngestRequest, proto};
use prost::Message;
use std::fs::{OpenOptions, create_dir, remove_dir_all, write};
use std::io::Write as _;

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
    // Phase 0.6: `publish` only durably enqueues now -- it must not fan out
    // inline, so the fanout publisher sees zero calls right after admission
    // accepts the event. Driving `replay_pending` is what actually delivers
    // it, off the admission call stack entirely (see `spawn_fanout_worker`).
    outboxed
        .publish(&event)
        .expect("first publish durably enqueues");
    assert_eq!(
        outboxed.publisher.0, 0,
        "publish must not fan out inline -- that is the dedicated fanout worker's job"
    );
    outboxed
        .replay_pending()
        .expect("replay drains the freshly enqueued row");
    assert_eq!(outboxed.publisher.0, 1);

    // A second `publish` of the now-complete event must still be a no-op:
    // no re-enqueue, no second fanout call.
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

/// Fails fanout for exactly one configured event id and succeeds for every
/// other event -- the "sink that 4xx/5xx's forever for a single valid event"
/// scenario from the finding, as opposed to a malformed/poison row (which
/// `pending`/`pending_batch` quarantine separately, before replay ever sees
/// it).
struct SinglePoisonPublisher {
    poison_event_id: String,
    published: Vec<String>,
}

impl EventPublisher for SinglePoisonPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<crate::PublishOutcome, GatewayError> {
        if event.event_id == self.poison_event_id {
            return Err(GatewayError::publish_failed());
        }
        self.published.push(event.event_id.clone());
        Ok(crate::PublishOutcome::Published)
    }
}

#[test]
fn one_permanently_failing_event_does_not_block_the_rest_of_the_replay_batch() {
    use crate::outbox::PendingEventReplayer;

    let base = std::env::temp_dir().join(format!(
        "apex-outbox-replay-isolation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let mut outbox = FileOutbox::open(&path, &base, 8).unwrap();
    let poison = sample_event("018f5c91-2d88-7c00-8000-0000000000a1");
    let good_events = [
        sample_event("018f5c91-2d88-7c00-8000-0000000000a2"),
        sample_event("018f5c91-2d88-7c00-8000-0000000000a3"),
        sample_event("018f5c91-2d88-7c00-8000-0000000000a4"),
    ];
    outbox.enqueue(&poison).unwrap();
    for event in &good_events {
        outbox.enqueue(event).unwrap();
    }

    let publisher = SinglePoisonPublisher {
        poison_event_id: poison.event_id.clone(),
        published: Vec::new(),
    };
    let mut outboxed = OutboxedPublisher::new(publisher, outbox);

    // Regression target: with the old `?`-propagating loop, whichever of
    // these four rows the backend's (unordered, in this in-process test)
    // iteration visited first would decide the outcome -- if the poison row
    // came first, every other row silently never got attempted at all. The
    // fix processes every row unconditionally, so the outcome no longer
    // depends on iteration order.
    outboxed
        .replay_pending()
        .expect("one isolated publish failure must not surface as a hard replay error");

    let mut published = outboxed.publisher().published.clone();
    published.sort();
    let mut expected: Vec<String> = good_events.iter().map(|e| e.event_id.clone()).collect();
    expected.sort();
    assert_eq!(
        published, expected,
        "every non-poison event in the batch must still be published"
    );

    let remaining = outboxed.outbox_mut().pending();
    assert_eq!(
        remaining.len(),
        1,
        "only the permanently-failing event should remain pending"
    );
    assert_eq!(remaining[0].event_id, poison.event_id);

    remove_dir_all(base).unwrap();
}

/// Fails every publish it is asked to perform, counting attempts.
#[derive(Default)]
struct AlwaysFailingPublisher(usize);

impl EventPublisher for AlwaysFailingPublisher {
    fn publish(&mut self, _event: &IngestRequest) -> Result<crate::PublishOutcome, GatewayError> {
        self.0 += 1;
        Err(GatewayError::publish_failed())
    }
}

#[test]
fn a_permanently_failing_event_is_quarantined_after_the_replay_ceiling_instead_of_retried_forever()
 {
    use crate::outbox::PendingEventReplayer;

    let base = std::env::temp_dir().join(format!(
        "apex-outbox-replay-ceiling-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
    let poison = sample_event("018f5c91-2d88-7c00-8000-0000000000b1");
    outbox.enqueue(&poison).unwrap();

    let mut outboxed = OutboxedPublisher::new(AlwaysFailingPublisher::default(), outbox);

    // `FileOutbox::reschedule` (outbox/file_ops.rs) enforces
    // MAX_PERSISTED_ATTEMPTS = 8: attempts 1..=7 push the row's
    // `next_attempt_at` out and keep it pending; attempt 8 quarantines it
    // instead of scheduling a 9th. `FileOutbox::pending()` (unlike
    // `pending_batch`, which Postgres uses in production and applies the
    // `next_attempt_at <= now()` gate server-side) does not itself gate on
    // that deadline, so this loop reaches the ceiling without advancing a
    // clock.
    for _ in 0..8 {
        outboxed
            .replay_pending()
            .expect("a failing publish must not surface as a hard replay error");
    }

    assert_eq!(
        outboxed.publisher().0,
        8,
        "every attempt up to the ceiling must actually call publish"
    );
    assert!(
        outboxed.outbox_mut().pending().is_empty(),
        "the row must stop being offered for replay once quarantined"
    );
    assert_eq!(
        outboxed.outbox_mut().quarantined_batch(4).unwrap().len(),
        1,
        "the row must be quarantined, not lost"
    );

    // The failure mode this guards against: retried forever. One more cycle
    // must not call publish again for a row that is no longer pending.
    outboxed.replay_pending().unwrap();
    assert_eq!(outboxed.publisher().0, 8);

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

/// A trailing write torn by a crash mid-`write_all`/before `sync_data()`
/// returned must not be indistinguishable from real corruption: it was never
/// acknowledged to any caller, so it is always safe to discard. The journal
/// must load successfully, keep every record that parsed cleanly before the
/// torn tail, and self-heal by truncating the torn bytes off the file.
#[test]
fn file_outbox_recovers_from_a_torn_trailing_record() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-torn-trailing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let good = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        assert_eq!(outbox.enqueue(&good).unwrap(), EnqueueResult::Enqueued);
    }
    let good_len = std::fs::metadata(&path).unwrap().len();

    // Simulate the crash: the next record's bytes only partially made it to
    // disk (process/OS died mid-`write_all`, before the trailing `\n` and
    // `sync_data()`), leaving an unparseable, newline-less fragment at EOF.
    let torn_source = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    let full_line = serde_json::json!({
        "op": "pending",
        "workspace_id": "acme",
        "namespace_id": "prod",
        "event_id": torn_source.event_id,
        "envelope": torn_source.envelope,
    });
    let full_line_bytes = serde_json::to_vec(&full_line).unwrap();
    let torn_prefix = &full_line_bytes[..full_line_bytes.len() / 2];
    {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(torn_prefix).unwrap();
    }

    let mut reopened = FileOutbox::open(&path, &base, 4)
        .expect("a torn trailing record must not permanently block the journal from loading");
    assert_eq!(reopened.pending(), vec![good.clone()]);
    assert_eq!(
        reopened.enqueue(&good).unwrap(),
        EnqueueResult::AlreadyPending
    );

    // Self-healing: the torn fragment was truncated off on load, so the file
    // is back to exactly the last known-good state.
    assert_eq!(std::fs::metadata(&path).unwrap().len(), good_len);

    drop(reopened);
    let mut final_open = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(final_open.pending(), vec![good]);
    remove_dir_all(base).unwrap();
}

/// A malformed record in the MIDDLE of the file — even with a good record
/// after it — must keep failing closed exactly as before. Guessing at intent
/// there would risk silently dropping committed state.
#[test]
fn file_outbox_still_fails_closed_on_a_corrupt_middle_record_with_a_good_record_after_it() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-corrupt-middle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let first = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    let second = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    let line1 = serde_json::json!({
        "op": "pending",
        "workspace_id": "acme",
        "namespace_id": "prod",
        "event_id": first.event_id,
        "envelope": first.envelope,
    });
    let line3 = serde_json::json!({
        "op": "pending",
        "workspace_id": "acme",
        "namespace_id": "prod",
        "event_id": second.event_id,
        "envelope": second.envelope,
    });
    write(
        &path,
        format!(
            "{}\n{{\"op\":\"pending\"}}\n{}\n",
            serde_json::to_string(&line1).unwrap(),
            serde_json::to_string(&line3).unwrap()
        ),
    )
    .unwrap();
    let error = FileOutbox::open(&path, &base, 4).unwrap_err();
    assert_eq!(
        error.code,
        crate::GatewayErrorCode::InvalidOutboxConfiguration
    );
    remove_dir_all(base).unwrap();
}

/// Phase 0.6 item 4 (continuous drain): `PendingEventReplayer::replay_pending`
/// now returns whether it actually settled work, which is the signal
/// `spawn_fanout_worker` uses to decide whether to loop again immediately or
/// fall back to sleeping `interval`. These three cases pin the contract at
/// the `OutboxedPublisher` level, independent of the worker loop itself.
mod continuous_drain_signal {
    use super::*;
    use crate::outbox::PendingEventReplayer;

    #[test]
    fn empty_outbox_reports_no_work_done() {
        let mut outboxed = OutboxedPublisher::new(
            CountingPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        );
        assert!(
            !outboxed.replay_pending().unwrap(),
            "nothing pending must not signal a drain-again cycle"
        );
    }

    #[test]
    fn a_settled_event_reports_work_done() {
        let mut outboxed = OutboxedPublisher::new(
            CountingPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        );
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-8000-0000000000c1",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        outboxed.publish(&event).expect("durably enqueue");
        assert!(
            outboxed.replay_pending().unwrap(),
            "a cycle that durably settles an event must signal more draining may be worthwhile"
        );
        // A second cycle over an outbox with nothing left pending goes back
        // to reporting no work, not a stale "true" from the previous cycle.
        assert!(!outboxed.replay_pending().unwrap());
    }

    #[test]
    fn a_cycle_where_every_row_fails_reports_no_work_done() {
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-8000-0000000000c2",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        let mut outbox = InMemoryOutbox::new(4).unwrap();
        outbox.enqueue(&event).unwrap();
        let mut outboxed = OutboxedPublisher::new(AlwaysFailingPublisher::default(), outbox);
        // Rows were claimed (pending was non-empty) but nothing settled --
        // this must report `false` exactly like the empty case, so
        // `spawn_fanout_worker` falls back to its `interval` throttle instead
        // of spinning against a sink that is still down.
        assert!(
            !outboxed.replay_pending().unwrap(),
            "a cycle that claims rows but settles none of them must not signal continuous drain"
        );
        assert_eq!(outboxed.publisher().0, 1);
    }
}

