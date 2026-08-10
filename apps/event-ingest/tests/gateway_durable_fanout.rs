//! `DurableFanoutPublisher` and `RetryingDurableSink`: JetStream/ClickHouse/
//! archive write ordering, stopping the fanout on a downstream failure, and
//! containment of downstream sink and transport panics as safe internal
//! errors, plus bounded downstream retry semantics.
//!
//! See the sibling `gateway_*.rs` files for the rest of this suite:
//! auth admission, JetStream publishing, envelope validation,
//! idempotency/scope, diagnostics, and transport configuration.

use apex_event_ingest::{
    ArchivePublisher, ClickHousePublisher, DurableEventSink, DurableFanoutPublisher,
    EventPublisher, GatewayError, GatewayErrorCode, IngestRequest, JetStreamTransport,
    RetryingDurableSink, proto,
};
use prost::Message;

const FIXTURE_EVENT_HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

#[derive(Default)]
struct RecordingTransport {
    published: Vec<(String, String, Vec<u8>)>,
}

#[derive(Default)]
struct RecordingSink {
    writes: usize,
    fail: bool,
    panic: bool,
}

impl DurableEventSink for RecordingSink {
    fn write_event(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
        self.writes += 1;
        if self.panic {
            panic!("simulated downstream sink panic");
        }
        if self.fail {
            Err(GatewayError::publish_failed())
        } else {
            Ok(())
        }
    }
}

impl ClickHousePublisher for RecordingSink {}
impl ArchivePublisher for RecordingSink {}

struct FlakySink {
    remaining_failures: usize,
    attempts: usize,
}

impl DurableEventSink for FlakySink {
    fn write_event(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
        self.attempts += 1;
        if self.remaining_failures > 0 {
            self.remaining_failures -= 1;
            Err(GatewayError::publish_failed())
        } else {
            Ok(())
        }
    }
}

struct NonRetrySink {
    attempts: usize,
}

impl DurableEventSink for NonRetrySink {
    fn write_event(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
        self.attempts += 1;
        Err(GatewayError::scope_denied())
    }
}

struct PanickingTransport;

impl JetStreamTransport for PanickingTransport {
    fn publish_event(
        &mut self,
        _subject: &str,
        _message_id: &str,
        _payload: &[u8],
    ) -> Result<(), GatewayError> {
        panic!("simulated transport panic")
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
fn durable_fanout_orders_jetstream_clickhouse_and_archive_writes() {
    let mut fanout = DurableFanoutPublisher::new(
        RecordingTransport::default(),
        RecordingSink::default(),
        RecordingSink::default(),
    );
    fanout
        .publish(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .expect("all durable projections acknowledge");
    assert_eq!(fanout.clickhouse().writes, 1);
    assert_eq!(fanout.archive().writes, 1);
    let _ = fanout.jetstream();
}

#[test]
fn durable_fanout_stops_before_archive_when_clickhouse_fails() {
    let mut fanout = DurableFanoutPublisher::new(
        RecordingTransport::default(),
        RecordingSink {
            writes: 0,
            fail: true,
            panic: false,
        },
        RecordingSink::default(),
    );
    let error = fanout
        .publish(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::PublishFailed);
    assert_eq!(fanout.clickhouse().writes, 1);
    assert_eq!(fanout.archive().writes, 0);
}

#[test]
fn durable_fanout_contains_downstream_sink_panics() {
    let mut fanout = DurableFanoutPublisher::new(
        RecordingTransport::default(),
        RecordingSink {
            writes: 0,
            fail: false,
            panic: true,
        },
        RecordingSink::default(),
    );
    let error = fanout
        .publish(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::Internal);
    assert_eq!(fanout.archive().writes, 0);
}

#[test]
fn downstream_retry_adapter_retries_only_bounded_transient_failures() {
    let mut sink = RetryingDurableSink::new(
        FlakySink {
            remaining_failures: 2,
            attempts: 0,
        },
        3,
    )
    .expect("valid downstream retry budget");
    sink.write_event(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .expect("third attempt succeeds");
    assert_eq!(sink.sink().attempts, 3);
}

#[test]
fn downstream_retry_adapter_rejects_unbounded_budgets_and_stops_non_retryable_errors() {
    let configuration_error = GatewayError::invalid_retry_configuration();
    assert!(configuration_error.summary.contains("durable publisher"));
    assert!(configuration_error.cause.contains("downstream load"));
    assert!(
        RetryingDurableSink::new(
            FlakySink {
                remaining_failures: 0,
                attempts: 0,
            },
            0,
        )
        .is_err()
    );
    assert!(
        RetryingDurableSink::new(
            FlakySink {
                remaining_failures: 0,
                attempts: 0,
            },
            9,
        )
        .is_err()
    );

    let mut sink = RetryingDurableSink::new(NonRetrySink { attempts: 0 }, 8)
        .expect("valid downstream retry budget");
    let error = sink
        .write_event(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::ScopeDenied);
    assert_eq!(sink.sink().attempts, 1);
}

#[test]
fn durable_fanout_contains_jetstream_transport_panics_before_downstream_writes() {
    let mut fanout = DurableFanoutPublisher::new(
        PanickingTransport,
        RecordingSink::default(),
        RecordingSink::default(),
    );
    let error = fanout
        .publish(&event("018f5c91-2d88-7c00-8000-000000000001"))
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::Internal);
    assert_eq!(fanout.clickhouse().writes, 0);
    assert_eq!(fanout.archive().writes, 0);
}
