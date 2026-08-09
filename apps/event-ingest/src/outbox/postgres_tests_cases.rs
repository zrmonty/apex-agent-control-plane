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
    IngestRequest::new(event_id, "acme", "prod", envelope.encode_to_vec())
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

// ---------------------------------------------------------------------------
// Adversarial concurrency (see idempotency/postgres_tests.rs for the rationale)
// ---------------------------------------------------------------------------

fn unique_event_id(tag: u64) -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u64) & 0xffff)
        .unwrap_or(0);
    format!("018f5c91-2d88-7c00-8000-{:012x}", (tag << 16) | nonce)
}

/// N replicas enqueueing the SAME event at the same instant.
///
/// Exactly one may take ownership of the fanout. Everyone else must be told
/// the row is already pending, which is what makes `OutboxedPublisher` answer
/// IDEMPOTENCY_IN_PROGRESS instead of fanning the event out a second time.
#[test]
fn postgres_outbox_parallel_enqueue_of_one_event_yields_one_owner() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    const WRITERS: usize = 16;
    let event_id = unique_event_id(0xd0);
    let event = valid_outbox_event(&event_id);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for _ in 0..WRITERS {
        let url = url.clone();
        let event = event.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut outbox = PostgresOutbox::connect(&url, 4096).expect("connect");
            barrier.wait();
            outbox.enqueue(&event)
        }));
    }

    let mut enqueued = 0;
    let mut already_pending = 0;
    let mut internal = 0;
    let mut other = Vec::new();
    for handle in handles {
        match handle.join().expect("writer thread") {
            Ok(EnqueueResult::Enqueued) => enqueued += 1,
            Ok(EnqueueResult::AlreadyPending) => already_pending += 1,
            Ok(result) => other.push(format!("{result:?}")),
            Err(error) if error.code == crate::GatewayErrorCode::Internal => internal += 1,
            Err(error) => other.push(error.code.as_str().to_owned()),
        }
    }

    assert_eq!(
        enqueued, 1,
        "{enqueued} replicas took ownership of one outbox row \
         (already_pending={already_pending}, internal={internal}, other={other:?})"
    );
    assert!(
        other.is_empty(),
        "unexpected outcomes racing one event: {other:?}"
    );
    assert_eq!(
        internal, 0,
        "{internal} of {WRITERS} concurrent enqueues lost the primary-key race \
         and were reported as INTERNAL_FAILURE instead of AlreadyPending"
    );
    assert_eq!(
        already_pending,
        WRITERS - 1,
        "every replica that lost the race must see the row as already pending"
    );
}

/// Concurrent replicas racing one event id with DIFFERENT envelopes.
///
/// One envelope owns the key. Every divergent one must be a typed idempotency
/// conflict, because that is the signal a reused `event_id` carrying changed
/// content is supposed to raise.
#[test]
fn postgres_outbox_parallel_enqueue_with_divergent_envelopes_conflicts() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    const WRITERS: usize = 8;
    let event_id = unique_event_id(0xd1);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let url = url.clone();
        let event_id = event_id.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut outbox = PostgresOutbox::connect(&url, 4096).expect("connect");
            // Same key, different bytes: divergent content under one id.
            let mut event = valid_outbox_event(&event_id);
            event.envelope.extend_from_slice(&[0u8; 1][..index.min(1)]);
            barrier.wait();
            outbox.enqueue(&event)
        }));
    }

    let mut enqueued = 0;
    let mut conflicts = 0;
    let mut already_pending = 0;
    let mut internal = 0;
    for handle in handles {
        match handle.join().expect("writer thread") {
            Ok(EnqueueResult::Enqueued) => enqueued += 1,
            Ok(EnqueueResult::AlreadyPending | EnqueueResult::AlreadyComplete) => {
                already_pending += 1
            }
            Err(error) if error.code == crate::GatewayErrorCode::IdempotencyConflict => {
                conflicts += 1
            }
            Err(error) if error.code == crate::GatewayErrorCode::Internal => internal += 1,
            Err(error) => panic!("unexpected error: {}", error.code.as_str()),
        }
    }

    assert_eq!(
        enqueued, 1,
        "{enqueued} replicas took ownership of one outbox row"
    );
    assert_eq!(
        internal, 0,
        "{internal} divergent-envelope writers were reported as INTERNAL_FAILURE \
         instead of a typed idempotency conflict"
    );
    assert_eq!(
        conflicts + already_pending,
        WRITERS - 1,
        "every losing replica must get a typed answer (conflict or already-pending)"
    );
}

