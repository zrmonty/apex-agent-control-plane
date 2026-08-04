use super::*;
use crate::outbox::{EventOutbox, InMemoryOutbox, OutboxedPublisher};
use crate::{
    GatewayError, GatewayErrorCode, IdempotencyKey, IdempotencyStore, InMemoryIdempotencyStore,
    InMemoryPublisher, IngestRequest, SecuritySignal, proto,
};
use prost::Message;

const EVENT: &str = "018f5c91-2d88-7c00-8000-000000000001";

fn scope_caller() -> crate::Caller {
    crate::Caller::authenticated_for_agent("spiffe://apex/test-reader", "agent", ["acme/prod"])
        .expect("valid bound test caller")
}

fn sample_envelope(event_id: &str) -> proto::EventEnvelope {
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
    envelope
}

fn sample_request(event_id: &str) -> IngestRequest {
    let envelope = sample_envelope(event_id);
    IngestRequest::new(event_id, "acme", "prod", envelope.encode_to_vec())
}

#[test]
fn gateway_rejects_unbound_authenticated_callers_before_publishing() {
    let mut gateway = IngestGateway::new(InMemoryPublisher::default());
    let unbound = crate::Caller::authenticated("spiffe://apex/test", ["acme/prod"]);

    let error = gateway.ingest(&unbound, sample_request(EVENT)).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::Unauthenticated);
    assert!(gateway.publisher().published_event_ids().is_empty());
}

#[derive(Default)]
struct FailingPublisher {
    fail: bool,
    calls: usize,
}

impl EventPublisher for FailingPublisher {
    fn publish(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
        self.calls += 1;
        if self.fail {
            Err(GatewayError::publish_failed())
        } else {
            Ok(())
        }
    }
}

#[test]
fn with_idempotency_store_and_publish_failure_aborts_reservation() {
    let store = InMemoryIdempotencyStore::new(4).unwrap();
    let mut gateway = IngestGateway::with_idempotency_store(
        FailingPublisher {
            fail: true,
            calls: 0,
        },
        Box::new(store),
    )
    .with_security_store(8)
    .unwrap();
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
            .expect("valid bound test caller");
    let err = gateway.ingest(&caller, sample_request(EVENT)).unwrap_err();
    assert_eq!(err.code, GatewayErrorCode::PublishFailed);
    assert_eq!(gateway.publisher().calls, 1);
    // After abort, a second attempt with a healthy publisher path is not available
    // here without swapping the publisher; re-ingest with same failing publisher
    // should still reach publish rather than report in-progress.
    let err = gateway.ingest(&caller, sample_request(EVENT)).unwrap_err();
    assert_eq!(err.code, GatewayErrorCode::PublishFailed);
    assert_eq!(gateway.publisher().calls, 2);
    assert!(
        gateway
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(gateway.security_store().is_some());
}

#[test]
fn in_progress_reservation_returns_idempotency_in_progress() {
    let mut store = InMemoryIdempotencyStore::new(4).unwrap();
    let event = sample_request(EVENT);
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&event.envelope).into()
    };
    let _ = store
        .reserve(
            IdempotencyKey {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
                event_id: EVENT.into(),
            },
            hash,
        )
        .unwrap();
    let mut gateway =
        IngestGateway::with_idempotency_store(InMemoryPublisher::default(), Box::new(store));
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
            .expect("valid bound test caller");
    assert_eq!(
        gateway.ingest(&caller, event).unwrap_err().code,
        GatewayErrorCode::IdempotencyInProgress
    );
}

#[test]
fn adapter_replays_pending_and_records_rejected_envelope_signals() {
    let mut outboxed = OutboxedPublisher::new(
        InMemoryPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    );
    let event = sample_request(EVENT);
    outboxed.outbox.enqueue(&event).expect("seed pending");
    let mut adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(outboxed));
    adapter.replay_pending().expect("replay drains");
    assert_eq!(
        adapter
            .gateway()
            .publisher()
            .publisher()
            .published_event_ids(),
        &[EVENT]
    );

    let mut secured = AuthenticatedIngestAdapter::new(
        IngestGateway::new(InMemoryPublisher::default())
            .with_security_store(8)
            .unwrap(),
    );
    let envelope = sample_envelope(EVENT);
    secured.record_security_signal(SecuritySignal::AuthAbuse, &envelope);
    assert!(
        !secured
            .gateway()
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn caller_subject_is_available_for_audit() {
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/workload", "agent", ["acme/prod"])
            .expect("valid bound test caller");
    assert_eq!(caller.subject(), Some("spiffe://apex/workload"));
    assert!(crate::Caller::anonymous().subject().is_none());
}

struct FailCommitStore {
    next_token: u64,
}

impl IdempotencyStore for FailCommitStore {
    fn reserve(
        &mut self,
        _key: IdempotencyKey,
        _payload_hash: [u8; 32],
    ) -> Result<crate::ReservationResult, GatewayError> {
        let token = self.next_token;
        self.next_token += 1;
        Ok(crate::ReservationResult::Reserved(
            crate::IdempotencyReservation { token },
        ))
    }

    fn commit(&mut self, _reservation: crate::IdempotencyReservation) -> Result<(), GatewayError> {
        Err(GatewayError::internal())
    }

    fn abort(&mut self, _reservation: crate::IdempotencyReservation) {}
}

#[test]
fn commit_failure_reconciles_when_publisher_supports_it() {
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
            .expect("valid bound test caller");
    // Outboxed publisher can reconcile commit failure.
    let mut reconciling = IngestGateway::with_idempotency_store(
        OutboxedPublisher::new(
            InMemoryPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        ),
        Box::new(FailCommitStore { next_token: 1 }),
    );
    assert_eq!(
        reconciling
            .ingest(&caller, sample_request(EVENT))
            .unwrap_err()
            .code,
        GatewayErrorCode::Internal
    );
    assert!(reconciling.publisher().can_reconcile_commit_failure());

    // Plain publisher retains the uncertain reservation (default trait method).
    let mut plain = IngestGateway::with_idempotency_store(
        InMemoryPublisher::default(),
        Box::new(FailCommitStore { next_token: 1 }),
    );
    assert!(!plain.publisher().can_reconcile_commit_failure());
    assert_eq!(
        plain
            .ingest(&caller, sample_request(EVENT))
            .unwrap_err()
            .code,
        GatewayErrorCode::Internal
    );
}

#[test]
fn security_journal_backend_exposes_findings() {
    let root = std::env::temp_dir().join(format!(
        "apex-gateway-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("findings.jsonl");
    let journal = crate::FindingJournal::open(&path, &root, 8).unwrap();
    let mut gateway =
        IngestGateway::new(InMemoryPublisher::default()).with_security_journal(journal);
    assert!(gateway.security_store().is_none());
    assert!(
        gateway
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["other/scope"])
            .expect("valid bound test caller");
    let _ = gateway.ingest(&caller, sample_request(EVENT));
    assert!(
        !gateway
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejected_envelope_signal_ignores_invalid_scope_or_event_id() {
    let mut gateway = IngestGateway::new(InMemoryPublisher::default())
        .with_security_store(4)
        .unwrap();
    let mut envelope = sample_envelope(EVENT);
    envelope.scope = None;
    gateway.record_rejected_envelope_signal(SecuritySignal::AuthAbuse, &envelope);
    assert!(
        gateway
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
    envelope = sample_envelope(EVENT);
    envelope.event_id = "not-a-uuid".into();
    gateway.record_rejected_envelope_signal(SecuritySignal::AuthAbuse, &envelope);
    assert!(
        gateway
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn adapter_maps_scope_denial_into_security_findings() {
    let mut adapter = AuthenticatedIngestAdapter::new(
        IngestGateway::new(InMemoryPublisher::default())
            .with_security_store(8)
            .unwrap(),
    );
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["other/scope"])
            .expect("valid bound test caller");
    let err = adapter
        .ingest_envelope(&caller, sample_envelope(EVENT))
        .unwrap_err();
    assert_eq!(err.code, GatewayErrorCode::ScopeDenied);
    assert!(
        !adapter
            .gateway()
            .security_findings_for_scope(&scope_caller(), "acme", "prod")
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn jetstream_publisher_rejects_invalid_event_id() {
    #[derive(Default)]
    struct NoopTransport;
    impl crate::JetStreamTransport for NoopTransport {
        fn publish_event(
            &mut self,
            _subject: &str,
            _message_id: &str,
            _payload: &[u8],
        ) -> Result<(), GatewayError> {
            Ok(())
        }
    }
    let mut publisher = crate::JetStreamPublisher::new(NoopTransport);
    let bad = IngestRequest::new("not-a-uuid", "acme", "prod", b"payload".to_vec());
    assert_eq!(
        publisher.publish(&bad).unwrap_err().code,
        GatewayErrorCode::InvalidEventId
    );
}
