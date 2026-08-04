#![cfg(feature = "test-support")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use apex_event_ingest::{
    ArchivePublisher, AuthenticatedGrpcService, AuthenticatedIngestAdapter, BearerTokenResolver,
    BearerTokenVerifier, Caller, ClickHousePublisher, DurableEventSink, DurableFanoutPublisher,
    GatewayError, IngestGateway, JetStreamTransport, bounded_event_ingest_server, proto,
};
use tonic::metadata::MetadataValue;

const EVENT_ID: &str = "018f5c91-2d88-7c00-8000-000000000001";
const EVENT_HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

#[derive(Clone, Default)]
struct DurableState {
    jetstream: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    clickhouse: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    archive: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[derive(Clone)]
struct TestJetStream {
    state: DurableState,
}

impl JetStreamTransport for TestJetStream {
    fn publish_event(
        &mut self,
        _subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        put_idempotent(&self.state.jetstream, message_id, payload)
    }
}

#[derive(Clone)]
struct TestSink {
    state: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl DurableEventSink for TestSink {
    fn write_event(
        &mut self,
        event: &apex_event_ingest::IngestRequest,
    ) -> Result<(), GatewayError> {
        put_idempotent(&self.state, event.event_id(), event.envelope())
    }
}

impl ClickHousePublisher for TestSink {}
impl ArchivePublisher for TestSink {}

fn put_idempotent(
    state: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
    key: &str,
    payload: &[u8],
) -> Result<(), GatewayError> {
    let mut records = state.lock().expect("test durable state lock");
    if let Some(original) = records.get(key) {
        if original == payload {
            return Ok(());
        }
        return Err(GatewayError::idempotency_conflict());
    }
    records.insert(key.to_owned(), payload.to_vec());
    Ok(())
}

struct TestResolver;

impl BearerTokenResolver for TestResolver {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
        if token == "e2e-token" {
            Ok(Caller::authenticated_for_agent(
                "e2e-test",
                "agent",
                ["acme/prod"],
            )?)
        } else {
            Err(GatewayError::unauthenticated())
        }
    }
}

fn envelope(event_id: &str, hash: &str) -> proto::EventEnvelope {
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
            event_hash: hash.to_owned(),
        }),
        schema_version: 1,
    }
}

fn service(
    state: DurableState,
) -> AuthenticatedGrpcService<
    DurableFanoutPublisher<TestJetStream, TestSink, TestSink>,
    BearerTokenVerifier<TestResolver>,
> {
    let fanout = DurableFanoutPublisher::new(
        TestJetStream {
            state: state.clone(),
        },
        TestSink {
            state: state.clickhouse,
        },
        TestSink {
            state: state.archive,
        },
    );
    AuthenticatedGrpcService::new(
        AuthenticatedIngestAdapter::new(IngestGateway::new(fanout)),
        BearerTokenVerifier::new(TestResolver),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_grpc_path_replays_across_restart_and_preserves_conflicts() {
    let state = DurableState::default();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
    let address = listener.local_addr().expect("test address");
    drop(listener);

    let shutdown = tokio::sync::oneshot::channel::<()>();
    let first_state = state.clone();
    let first_server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(bounded_event_ingest_server(service(first_state)))
            .serve_with_shutdown(address, async {
                let _ = shutdown.1.await;
            })
            .await
            .expect("first gRPC server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let channel = tonic::transport::Channel::from_shared(format!("http://{address}"))
        .expect("client endpoint")
        .connect()
        .await
        .expect("connect to first gRPC server");
    let mut client = proto::event_ingest_client::EventIngestClient::new(channel);
    let mut request = tonic::Request::new(envelope(EVENT_ID, EVENT_HASH));
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer e2e-token").expect("metadata"),
    );
    let first = client
        .ingest(request)
        .await
        .expect("first ingest")
        .into_inner();
    assert!(!first.duplicate);
    assert_eq!(state.jetstream.lock().unwrap().len(), 1);
    assert_eq!(state.clickhouse.lock().unwrap().len(), 1);
    assert_eq!(state.archive.lock().unwrap().len(), 1);

    let _ = shutdown.0.send(());
    first_server.await.expect("stop first server");

    let restart_shutdown = tokio::sync::oneshot::channel::<()>();
    let restarted_state = state.clone();
    let restarted_server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(bounded_event_ingest_server(service(restarted_state)))
            .serve_with_shutdown(address, async {
                let _ = restart_shutdown.1.await;
            })
            .await
            .expect("restarted gRPC server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let channel = tonic::transport::Channel::from_shared(format!("http://{address}"))
        .expect("client endpoint")
        .connect()
        .await
        .expect("connect after restart");
    let mut client = proto::event_ingest_client::EventIngestClient::new(channel);
    let mut replay = tonic::Request::new(envelope(EVENT_ID, EVENT_HASH));
    replay.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer e2e-token").expect("metadata"),
    );
    let duplicate = client
        .ingest(replay)
        .await
        .expect("duplicate replay")
        .into_inner();
    assert!(
        !duplicate.duplicate,
        "gateway restart loses only its volatile index; sinks deduplicate durably"
    );
    assert_eq!(state.jetstream.lock().unwrap().len(), 1);
    assert_eq!(state.clickhouse.lock().unwrap().len(), 1);
    assert_eq!(state.archive.lock().unwrap().len(), 1);

    let mut changed = envelope(EVENT_ID, EVENT_HASH);
    changed.run_id = "different-run".to_owned();
    let changed_hash = apex_event_ingest::IngestRequest::canonical_hash_for_test(&changed)
        .expect("hash changed event");
    changed.integrity.as_mut().expect("integrity").event_hash = changed_hash;
    let mut conflict = tonic::Request::new(changed);
    conflict.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer e2e-token").expect("metadata"),
    );
    let error = client
        .ingest(conflict)
        .await
        .expect_err("changed payload must conflict");
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("IDEMPOTENCY_CONFLICT"));
    assert_eq!(state.jetstream.lock().unwrap().len(), 1);
    assert_eq!(state.clickhouse.lock().unwrap().len(), 1);
    assert_eq!(state.archive.lock().unwrap().len(), 1);

    let provider_conflict = put_idempotent(&state.jetstream, EVENT_ID, b"changed")
        .expect_err("durable provider must preserve an event-id conflict");
    assert_eq!(
        provider_conflict.code,
        apex_event_ingest::GatewayErrorCode::IdempotencyConflict
    );

    let _ = restart_shutdown.0.send(());
    restarted_server.await.expect("stop restarted server");
}
