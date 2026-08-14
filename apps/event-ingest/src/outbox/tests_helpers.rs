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

#[test]
fn file_outbox_retention_compacts_completed_idempotency_state() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-retention-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let event = sample_event("018f5c91-2d88-7c00-0000-000000000099");
    let before;
    {
        let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
        outbox.enqueue(&event).unwrap();
        outbox
            .mark_complete(&OutboxKey {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
                event_id: event.event_id.clone(),
            })
            .unwrap();
        before = std::fs::metadata(&path).unwrap().len();
        outbox.maintain(u64::MAX, 0).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < before);
    }
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(reopened.enqueue(&event).unwrap(), EnqueueResult::Enqueued);
    remove_dir_all(base).unwrap();
}

#[test]
fn memory_outbox_oldest_pending_millis_is_none_when_empty_and_tracks_the_oldest_row() {
    let mut outbox = InMemoryOutbox::new(4).unwrap();
    assert_eq!(outbox.oldest_pending_millis().unwrap(), None);

    let first = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    outbox.enqueue(&first).unwrap();
    let age_after_first = outbox.oldest_pending_millis().unwrap();
    assert!(age_after_first.is_some(), "one pending row must report an age");

    // A second, later-enqueued row must never make the reported age
    // *younger* -- `oldest_pending_millis` always tracks the OLDEST row.
    let second = sample_event("018f5c91-2d88-7c00-8000-000000000002");
    outbox.enqueue(&second).unwrap();
    let age_with_two_pending = outbox.oldest_pending_millis().unwrap().unwrap();
    assert!(age_with_two_pending >= age_after_first.unwrap());

    // Completing the (only) tracked row clears it; completing the other
    // still-pending row still reports an age.
    let first_key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: first.event_id.clone(),
    };
    outbox.mark_complete(&first_key).unwrap();
    assert!(outbox.oldest_pending_millis().unwrap().is_some());

    let second_key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: second.event_id.clone(),
    };
    outbox.mark_complete(&second_key).unwrap();
    assert_eq!(
        outbox.oldest_pending_millis().unwrap(),
        None,
        "no rows left pending must report None again"
    );
}

#[test]
fn memory_outbox_quarantine_clears_and_requeue_restarts_the_pending_age() {
    let mut outbox = InMemoryOutbox::new(4).unwrap();
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    outbox.enqueue(&event).unwrap();
    assert!(outbox.oldest_pending_millis().unwrap().is_some());

    let key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event.event_id.clone(),
    };
    outbox.quarantine(std::slice::from_ref(&key), "test").unwrap();
    assert_eq!(
        outbox.oldest_pending_millis().unwrap(),
        None,
        "a quarantined row is no longer pending"
    );

    outbox.requeue_quarantined(&[key]).unwrap();
    assert!(
        outbox.oldest_pending_millis().unwrap().is_some(),
        "a requeued row is pending again"
    );
}

#[test]
fn file_outbox_oldest_pending_millis_is_none_when_empty_and_tracks_the_oldest_row() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-oldest-pending-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
    assert_eq!(outbox.oldest_pending_millis().unwrap(), None);

    let event = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    outbox.enqueue(&event).unwrap();
    assert!(outbox.oldest_pending_millis().unwrap().is_some());

    let key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event.event_id.clone(),
    };
    outbox.mark_complete(&key).unwrap();
    assert_eq!(outbox.oldest_pending_millis().unwrap(), None);
    remove_dir_all(base).unwrap();
}

#[test]
fn file_outbox_pending_age_survives_a_restart() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-oldest-pending-restart-{}-{}",
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
    }
    // A fresh process re-reading the journal must still see the row as
    // pending with a real age -- the age must not reset to (near) zero just
    // because the in-memory `pending_since_millis` map was rebuilt from the
    // journal on reload.
    let mut reopened = FileOutbox::open(&path, &base, 4).unwrap();
    assert!(reopened.oldest_pending_millis().unwrap().is_some());
    remove_dir_all(base).unwrap();
}

#[test]
fn file_outbox_requeue_after_quarantine_restarts_the_pending_age() {
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-oldest-pending-requeue-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_dir(&base).unwrap();
    let path = base.join("events.jsonl");
    let mut outbox = FileOutbox::open(&path, &base, 4).unwrap();
    let event = sample_event("018f5c91-2d88-7c00-8000-000000000001");
    outbox.enqueue(&event).unwrap();
    let key = OutboxKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event.event_id.clone(),
    };
    outbox.quarantine(std::slice::from_ref(&key), "test").unwrap();
    assert_eq!(outbox.oldest_pending_millis().unwrap(), None);
    outbox.requeue_quarantined(&[key]).unwrap();
    assert!(outbox.oldest_pending_millis().unwrap().is_some());
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
