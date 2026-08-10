//! `JetStreamPublisher` and `RetryingJetStreamTransport`: subject derivation
//! and encoding, pre-transport validation (unsafe subjects, oversized/empty
//! payloads, broker subject-length limits), transport failure classification,
//! and bounded retry semantics.
//!
//! See the sibling `gateway_*.rs` files for the rest of this suite:
//! auth admission, envelope validation, idempotency/scope, diagnostics,
//! transport configuration, and durable fanout.

use apex_event_ingest::{
    EventPublisher, GatewayError, GatewayErrorCode, IngestRequest, MAX_ENVELOPE_BYTES, proto,
};
use prost::Message;

const FIXTURE_EVENT_HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

#[derive(Default)]
struct RecordingTransport {
    published: Vec<(String, String, Vec<u8>)>,
}

struct FailingTransport;

struct FlakyTransport {
    remaining_failures: usize,
    attempts: usize,
}

struct NonRetryableTransport {
    attempts: usize,
}

impl apex_event_ingest::JetStreamTransport for FailingTransport {
    fn publish_event(
        &mut self,
        _subject: &str,
        _message_id: &str,
        _payload: &[u8],
    ) -> Result<(), GatewayError> {
        Err(GatewayError::publish_failed())
    }
}

impl apex_event_ingest::JetStreamTransport for NonRetryableTransport {
    fn publish_event(
        &mut self,
        _subject: &str,
        _message_id: &str,
        _payload: &[u8],
    ) -> Result<(), GatewayError> {
        self.attempts += 1;
        Err(GatewayError::scope_denied())
    }
}

impl apex_event_ingest::JetStreamTransport for FlakyTransport {
    fn publish_event(
        &mut self,
        _subject: &str,
        _message_id: &str,
        _payload: &[u8],
    ) -> Result<(), GatewayError> {
        self.attempts += 1;
        if self.attempts <= self.remaining_failures {
            Err(GatewayError::publish_failed())
        } else {
            Ok(())
        }
    }
}

impl apex_event_ingest::JetStreamTransport for RecordingTransport {
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        self.published
            .push((subject.to_owned(), message_id.to_owned(), payload.to_vec()));
        Ok(())
    }
}

fn event(event_id: &str) -> IngestRequest {
    IngestRequest::new(event_id, "acme", "prod", envelope(event_id).encode_to_vec())
}

fn envelope(event_id: &str) -> proto::EventEnvelope {
    proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2026-08-03T00:00:00.000000Z".to_owned(),
        r#type: 1,
        agent_id: "agent".to_owned(),
        run_id: "run-1".to_owned(),
        parent_run_id: None,
        trace_id: "trace-1".to_owned(),
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
            agent_code: "v1".to_owned(),
            prompt: "p1".to_owned(),
            model: "gpt-5".to_owned(),
        }),
        data: Some(prost_types::Struct::default()),
        integrity: Some(proto::Integrity {
            prev_hash: None,
            event_hash: FIXTURE_EVENT_HASH.to_owned(),
        }),
        schema_version: 1,
    }
}

#[test]
fn jetstream_publisher_derives_scope_subject_and_event_message_id() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = event("018f5c91-2d88-7c00-8000-000000000001");

    EventPublisher::publish(&mut publisher, &request).unwrap();

    let published = &publisher.transport().published[0];
    assert_eq!(published.0, "apex.events.x61636d65.x70726f64");
    assert_eq!(published.1, "018f5c91-2d88-7c00-8000-000000000001");
    assert_eq!(
        published.2,
        envelope("018f5c91-2d88-7c00-8000-000000000001").encode_to_vec()
    );
}

#[test]
fn jetstream_subject_encoding_keeps_dotted_scopes_as_single_tokens() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "acme.prod",
        "team:one",
        b"body".to_vec(),
    );

    EventPublisher::publish(&mut publisher, &request).unwrap();

    assert_eq!(
        publisher.transport().published[0].0,
        "apex.events.x61636d652e70726f64.x7465616d3a6f6e65"
    );
}

#[test]
fn jetstream_publisher_rejects_unsafe_subject_components_before_transport() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "acme\nprod",
        "prod",
        b"body".to_vec(),
    );

    let error = EventPublisher::publish(&mut publisher, &request).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::ScopeDenied);
    assert!(publisher.transport().published.is_empty());
}

#[test]
fn jetstream_publisher_rejects_subjects_that_exceed_broker_limits() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "w".repeat(200),
        "n".repeat(100),
        b"body".to_vec(),
    );

    let error = EventPublisher::publish(&mut publisher, &request).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::SubjectTooLong);
    assert!(publisher.transport().published.is_empty());
}

#[test]
fn jetstream_publisher_rejects_oversized_payloads_before_transport() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "acme",
        "prod",
        vec![b'x'; MAX_ENVELOPE_BYTES + 1],
    );

    let error = EventPublisher::publish(&mut publisher, &request).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::PayloadTooLarge);
    assert!(publisher.transport().published.is_empty());
}

#[test]
fn jetstream_publisher_rejects_empty_payloads_before_transport() {
    let transport = RecordingTransport::default();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(transport);
    let request = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-000000000001",
        "acme",
        "prod",
        Vec::new(),
    );

    let error = EventPublisher::publish(&mut publisher, &request).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidEnvelope);
    assert!(publisher.transport().published.is_empty());
}

#[test]
fn jetstream_publisher_preserves_safe_transport_failure_classification() {
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(FailingTransport);
    let error = EventPublisher::publish(
        &mut publisher,
        &event("018f5c91-2d88-7c00-8000-000000000001"),
    )
    .unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::PublishFailed);
    assert!(error.retryable);
    assert!(error.summary.contains("publish"));
    assert!(!error.summary.contains("acme"));
}

#[test]
fn retrying_transport_retries_only_bounded_transient_failures() {
    let retrying = apex_event_ingest::RetryingJetStreamTransport::new(
        FlakyTransport {
            remaining_failures: 2,
            attempts: 0,
        },
        3,
    )
    .unwrap();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(retrying);

    EventPublisher::publish(
        &mut publisher,
        &event("018f5c91-2d88-7c00-8000-000000000001"),
    )
    .unwrap();

    assert_eq!(publisher.transport().transport().attempts, 3);
}

#[test]
fn retrying_transport_rejects_unbounded_attempt_configuration() {
    let zero = apex_event_ingest::RetryingJetStreamTransport::new(FailingTransport, 0)
        .err()
        .unwrap();
    let too_many = apex_event_ingest::RetryingJetStreamTransport::new(FailingTransport, 9)
        .err()
        .unwrap();
    assert_eq!(zero.code, GatewayErrorCode::InvalidRetryConfiguration);
    assert_eq!(too_many.code, GatewayErrorCode::InvalidRetryConfiguration);
    assert!(zero.cause.contains("between 1 and 8"));
    assert!(!zero.summary.contains("token"));
}

#[test]
fn retrying_transport_never_retries_non_retryable_failures() {
    let retrying = apex_event_ingest::RetryingJetStreamTransport::new(
        NonRetryableTransport { attempts: 0 },
        8,
    )
    .unwrap();
    let mut publisher = apex_event_ingest::JetStreamPublisher::new(retrying);

    let error = EventPublisher::publish(
        &mut publisher,
        &event("018f5c91-2d88-7c00-8000-000000000001"),
    )
    .unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::ScopeDenied);
    assert_eq!(publisher.transport().transport().attempts, 1);
}

#[test]
fn jetstream_boundary_errors_include_actionable_ai_guidance() {
    let error = GatewayError::subject_too_long();
    let report = error.diagnostic_report("event-ingest.jetstream", "acme", "prod", None);
    let markdown = report.to_ai_markdown();

    assert!(markdown.contains("JETSTREAM_SUBJECT_TOO_LONG"));
    assert!(markdown.contains("workspace_id and namespace_id"));
    assert!(markdown.contains("at or below 256 bytes"));
    assert!(!markdown.contains("acme.prod"));
}
