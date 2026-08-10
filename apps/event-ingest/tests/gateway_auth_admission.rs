//! `AuthenticatedGrpcService` admission boundary: verifier rejection, bearer
//! header parsing, duplicate acknowledgement, oversized-message pre-verification
//! rejection, and panic containment.
//!
//! See the sibling `gateway_*.rs` files for the rest of this suite:
//! JetStream publishing, envelope validation, idempotency/scope, diagnostics,
//! transport configuration, and durable fanout.

use apex_event_ingest::{
    AuthenticatedGrpcService, AuthenticatedIngestAdapter, BearerTokenResolver, BearerTokenVerifier,
    Caller, CallerVerifier, GatewayError, InMemoryPublisher, IngestGateway, MAX_ENVELOPE_BYTES,
    bounded_event_ingest_server, proto,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tonic::metadata::MetadataMap;

const FIXTURE_EVENT_HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

fn caller() -> Caller {
    Caller::authenticated_for_agent(
        "spiffe://apex/workload/reference-agent",
        "agent",
        ["acme/prod"],
    )
    .expect("valid bound test caller")
}

struct TestVerifier {
    caller: Option<Caller>,
}

struct CountingVerifier {
    calls: Arc<AtomicUsize>,
}

struct PanickingVerifier;

struct TestTokenResolver;

impl BearerTokenResolver for TestTokenResolver {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
        if token == "valid-token" {
            Ok(caller())
        } else {
            Err(GatewayError::unauthenticated())
        }
    }
}

impl CallerVerifier for PanickingVerifier {
    fn verify(&self, _metadata: &MetadataMap) -> Result<Caller, GatewayError> {
        panic!("simulated verifier failure")
    }
}

impl CallerVerifier for CountingVerifier {
    fn verify(&self, _metadata: &MetadataMap) -> Result<Caller, GatewayError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(caller())
    }
}

impl CallerVerifier for TestVerifier {
    fn verify(&self, _metadata: &MetadataMap) -> Result<Caller, GatewayError> {
        self.caller
            .clone()
            .ok_or_else(GatewayError::unauthenticated)
    }
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

#[tokio::test]
async fn grpc_service_maps_verifier_rejection_without_exposing_details() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service = AuthenticatedGrpcService::new(adapter, TestVerifier { caller: None });
    let error = proto::event_ingest_server::EventIngest::ingest(
        &service,
        tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000001")),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        error.message(),
        "Authentication failed. Supply one valid bearer credential over the mTLS channel."
    );
}

#[tokio::test]
async fn bearer_verifier_accepts_valid_metadata_and_rejects_malformed_headers() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service =
        AuthenticatedGrpcService::new(adapter, BearerTokenVerifier::new(TestTokenResolver));
    let mut valid = tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000001"));
    valid
        .metadata_mut()
        .insert("authorization", "Bearer valid-token".parse().unwrap());
    let response = proto::event_ingest_server::EventIngest::ingest(&service, valid)
        .await
        .unwrap();
    assert!(!response.into_inner().duplicate);

    let mut malformed = tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000002"));
    malformed
        .metadata_mut()
        .insert("authorization", "Basic valid-token".parse().unwrap());
    let error = proto::event_ingest_server::EventIngest::ingest(&service, malformed)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    assert!(error.message().contains("Authentication failed"));
    assert!(!error.message().contains("valid-token"));

    let mut whitespace = tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000003"));
    whitespace
        .metadata_mut()
        .insert("authorization", "Bearer valid-token extra".parse().unwrap());
    let error = proto::event_ingest_server::EventIngest::ingest(&service, whitespace)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    assert!(error.message().contains("Authentication failed"));

    let mut oversized = tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000004"));
    oversized.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", "x".repeat(4097)).parse().unwrap(),
    );
    let error = proto::event_ingest_server::EventIngest::ingest(&service, oversized)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    assert!(error.message().contains("Authentication failed"));

    let mut duplicate = tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000005"));
    duplicate
        .metadata_mut()
        .append("authorization", "Bearer valid-token".parse().unwrap());
    duplicate
        .metadata_mut()
        .append("authorization", "Bearer attacker-token".parse().unwrap());
    let error = proto::event_ingest_server::EventIngest::ingest(&service, duplicate)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    assert!(error.message().contains("Authentication failed"));
    assert!(!error.message().contains("attacker-token"));
}

#[tokio::test]
async fn grpc_service_returns_duplicate_ack_for_retried_event() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service = AuthenticatedGrpcService::new(
        adapter,
        TestVerifier {
            caller: Some(caller()),
        },
    );
    let first = proto::event_ingest_server::EventIngest::ingest(
        &service,
        tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000001")),
    )
    .await
    .unwrap()
    .into_inner();
    let second = proto::event_ingest_server::EventIngest::ingest(
        &service,
        tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000001")),
    )
    .await
    .unwrap()
    .into_inner();

    assert!(!first.duplicate);
    assert!(second.duplicate);
}

#[test]
fn bounded_server_builder_is_available_for_deployments() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service = AuthenticatedGrpcService::new(
        adapter,
        TestVerifier {
            caller: Some(caller()),
        },
    );
    let _server = bounded_event_ingest_server(service);
}

#[tokio::test]
async fn grpc_service_rejects_oversized_messages_before_verification() {
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service = AuthenticatedGrpcService::new(
        adapter,
        CountingVerifier {
            calls: Arc::clone(&calls),
        },
    );
    let mut oversized = envelope("018f5c91-2d88-7c00-8000-000000000001");
    oversized.data = Some(prost_types::Struct {
        fields: [(
            "payload".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "x".repeat(MAX_ENVELOPE_BYTES),
                )),
            },
        )]
        .into_iter()
        .collect(),
    });

    let error =
        proto::event_ingest_server::EventIngest::ingest(&service, tonic::Request::new(oversized))
            .await
            .unwrap_err();

    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    assert!(error.message().starts_with(
        "PAYLOAD_TOO_LARGE: Ingest rejected an event envelope larger than the configured limit."
    ));
    assert!(error.message().contains("256 KiB"));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn grpc_service_contains_verifier_panics_as_safe_internal_status() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(InMemoryPublisher::default()));
    let service = AuthenticatedGrpcService::new(adapter, PanickingVerifier);
    let error = proto::event_ingest_server::EventIngest::ingest(
        &service,
        tonic::Request::new(envelope("018f5c91-2d88-7c00-8000-000000000001")),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(
        error
            .message()
            .starts_with("INTERNAL_FAILURE: Ingest encountered an internal service failure.")
    );
    assert!(error.message().contains("report correlation ID"));
    assert!(!error.message().contains("simulated verifier failure"));
}
