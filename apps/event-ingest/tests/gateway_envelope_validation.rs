//! `AuthenticatedIngestAdapter` envelope validation: structural completeness,
//! integrity/hash checks, control-event action data, secret-exposure
//! detection, nesting depth, timestamp shape, and AI-diagnostic rendering of
//! validation failures.
//!
//! See the sibling `gateway_*.rs` files for the rest of this suite:
//! auth admission, JetStream publishing, idempotency/scope, diagnostics,
//! transport configuration, and durable fanout.

use apex_event_ingest::{
    AuthenticatedIngestAdapter, Caller, FindingType, GatewayErrorCode, InMemoryPublisher,
    IngestGateway, IngestRequest, MAX_ENVELOPE_BYTES, proto,
};

const FIXTURE_EVENT_HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

fn caller() -> Caller {
    Caller::authenticated_for_agent(
        "spiffe://apex/workload/reference-agent",
        "agent",
        ["acme/prod"],
    )
    .expect("valid bound test caller")
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
fn authenticated_adapter_rejects_a_tampered_body_with_a_well_formed_hash() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000001");
    invalid.agent_id = "tampered-agent".to_owned();

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidIntegrity);
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);
}

#[test]
fn authenticated_adapter_admits_a_complete_protobuf_envelope() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));

    let response = adapter
        .ingest_envelope(&caller(), envelope("018f5c91-2d88-7c00-8000-000000000001"))
        .unwrap();

    assert!(!response.duplicate);
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 1);
}

#[test]
fn authenticated_adapter_rejects_incomplete_protobuf_envelopes_before_publishing() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000001");
    invalid.scope = None;

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidStructure);
    assert!(error.summary.contains("required"));
    assert!(error.cause.contains("scope"));
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);
}

#[test]
fn authenticated_adapter_rejects_control_events_with_invalid_action_data() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000001");
    invalid.r#type = 9;
    invalid.data = Some(prost_types::Struct {
        fields: [(
            "action".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("inject".to_owned())),
            },
        )]
        .into_iter()
        .collect(),
    });

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidStructure);
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);
}

#[test]
fn secret_exposure_is_detected_in_control_inject_and_recorded_as_a_finding() {
    let mut adapter = AuthenticatedIngestAdapter::new(
        IngestGateway::new(InMemoryPublisher::default())
            .with_security_store(8)
            .expect("security store capacity is valid"),
    );
    let mut inject = std::collections::BTreeMap::new();
    inject.insert(
        "action".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("inject".to_owned())),
        },
    );
    inject.insert(
        "enforcement".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "cooperative".to_owned(),
            )),
        },
    );
    inject.insert(
        "content_classification".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "untrusted".to_owned(),
            )),
        },
    );
    inject.insert(
        "content".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_owned(),
            )),
        },
    );
    let mut event = envelope("018f5c91-2d88-7c00-8000-000000000001");
    event.r#type = 9;
    event.data = Some(prost_types::Struct { fields: inject });

    let error = adapter.ingest_envelope(&caller(), event).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::SecretExposure);
    let findings = adapter
        .gateway()
        .security_findings_for_scope(&caller(), "acme", "prod")
        .unwrap()
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].finding_type, FindingType::SecretExposure);
}

#[test]
fn hash_and_identifier_fields_are_not_secret_false_positives() {
    let mut event = envelope("018f5c91-2d88-7c00-8000-000000000002");
    event.data = Some(prost_types::Struct {
        fields: [(
            "api_key_id".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("key-1".to_owned())),
            },
        )]
        .into_iter()
        .collect(),
    });
    event.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&event).unwrap();
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));

    assert!(adapter.ingest_envelope(&caller(), event).is_ok());
}

#[test]
fn authenticated_adapter_rejects_excessively_nested_struct_data() {
    let mut nested = prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue("leaf".to_owned())),
    };
    for _ in 0..70 {
        nested = prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: [("nested".to_owned(), nested)].into_iter().collect(),
            })),
        };
    }
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000002");
    invalid.data = Some(prost_types::Struct {
        fields: [("root".to_owned(), nested)].into_iter().collect(),
    });
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidStructure);
    assert!(
        adapter
            .gateway()
            .publisher()
            .published_event_ids()
            .is_empty()
    );
}

#[test]
fn authenticated_adapter_rejects_malformed_timestamp_instead_of_forwarding_it() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000001");
    invalid.timestamp = "2026-99-99T25:61:61Z".to_owned();

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidTimestamp);
    assert!(error.summary.contains("timestamp"));
    assert!(error.cause.contains("RFC 3339"));
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);
}

#[test]
fn authenticated_adapter_rejects_invalid_integrity_and_group_limits() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut invalid = envelope("018f5c91-2d88-7c00-8000-000000000001");
    invalid.integrity.as_mut().unwrap().event_hash = "A".repeat(64);
    invalid.scope.as_mut().unwrap().agent_group_ids = vec!["group".to_owned(); 129];

    let error = adapter.ingest_envelope(&caller(), invalid).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidIntegrity);
    assert!(error.summary.contains("integrity"));
    assert!(error.cause.contains("SHA-256"));
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);

    let mut duplicate_groups = envelope("018f5c91-2d88-7c00-8000-000000000002");
    duplicate_groups.scope.as_mut().unwrap().agent_group_ids =
        vec!["group".to_owned(), "group".to_owned()];
    let duplicate_error = adapter
        .ingest_envelope(&caller(), duplicate_groups)
        .unwrap_err();
    assert_eq!(duplicate_error.code, GatewayErrorCode::InvalidStructure);
}

#[test]
fn adapter_validation_errors_render_actionable_ai_handoffs() {
    let mut timestamp_adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut bad_timestamp = envelope("018f5c91-2d88-7c00-8000-000000000001");
    bad_timestamp.timestamp = "2026-02-30T00:00:00.000000Z".to_owned();
    let timestamp_error = timestamp_adapter
        .ingest_envelope(&caller(), bad_timestamp)
        .unwrap_err();

    let timestamp_report = timestamp_error.diagnostic_report("grpc.adapter", "acme", "prod", None);
    let timestamp_handoff = timestamp_report.to_ai_markdown();
    assert!(timestamp_handoff.contains("INVALID_TIMESTAMP"));
    assert!(timestamp_handoff.contains("RFC 3339"));
    assert!(timestamp_handoff.contains("YYYY-MM-DDTHH:MM:SS.ffffffZ"));

    let mut integrity_adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut bad_integrity = envelope("018f5c91-2d88-7c00-8000-000000000001");
    bad_integrity.integrity.as_mut().unwrap().event_hash = "A".repeat(64);
    let integrity_error = integrity_adapter
        .ingest_envelope(&caller(), bad_integrity)
        .unwrap_err();

    let integrity_handoff = integrity_error
        .diagnostic_report("grpc.adapter", "acme", "prod", None)
        .to_ai_markdown();
    assert!(integrity_handoff.contains("INVALID_INTEGRITY"));
    assert!(integrity_handoff.contains("SHA-256"));
    assert!(integrity_handoff.contains("event_hash"));
}

#[test]
fn authenticated_adapter_rejects_oversized_decoded_struct_before_serializing_for_publish() {
    let mut adapter =
        AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let mut oversized = envelope("018f5c91-2d88-7c00-8000-000000000001");
    oversized.data = Some(prost_types::Struct {
        fields: [(
            "content".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "x".repeat(MAX_ENVELOPE_BYTES + 1),
                )),
            },
        )]
        .into_iter()
        .collect(),
    });

    let error = adapter.ingest_envelope(&caller(), oversized).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::PayloadTooLarge);
    assert_eq!(error.grpc_status(), "RESOURCE_EXHAUSTED");
    assert_eq!(adapter.gateway().publisher().published_event_ids().len(), 0);
}
