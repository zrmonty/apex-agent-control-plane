use super::*;
use crate::outbox::{EnqueueResult, EventOutbox, FileOutbox, InMemoryOutbox, OutboxKey, OutboxedPublisher};
use crate::{
    AuthenticatedIngestAdapter, FileIdempotencyStore, GatewayErrorCode, IdempotencyKey,
    IdempotencyStore, InMemoryPublisher, IngestGateway, IngestRequest, ReservationResult,
    bounded_event_ingest_server,
};
use std::time::Duration;
use tonic::metadata::MetadataMap;

struct OkVerifier;

impl CallerVerifier for OkVerifier {
    fn verify(&self, _metadata: &MetadataMap) -> Result<crate::Caller, crate::GatewayError> {
        Ok(crate::Caller::authenticated(
            "spiffe://apex/test",
            ["acme/prod"],
        ))
    }
}

#[test]
fn authenticated_for_agent_rejects_untrusted_identity_shapes() {
    assert!(crate::Caller::authenticated_for_agent("", "agent", ["acme/prod"]).is_err());
    assert!(crate::Caller::authenticated_for_agent("subject\n", "agent", ["acme/prod"]).is_err());
    assert!(
        crate::Caller::authenticated_for_agent("subject", "agent with spaces", ["acme/prod"])
            .is_err()
    );
    assert!(
        crate::Caller::authenticated_for_agent("subject|pipe", "agent", ["acme/prod"]).is_err()
    );
    assert!(crate::Caller::authenticated_for_agent("spiffe://", "agent", ["acme/prod"]).is_err());
    assert!(crate::Caller::authenticated_for_agent("subject", "agent", ["acme"]).is_err());
    assert!(crate::Caller::authenticated_for_agent("subject", "agent", ["acme/prod/bad"]).is_err());
}

#[test]
fn authenticated_for_agent_bounds_scope_cardinality() {
    let scopes = (0..=256).map(|index| format!("workspace{index}/namespace"));
    assert!(crate::Caller::authenticated_for_agent("subject", "agent", scopes).is_err());
}

#[test]
fn authenticated_for_agent_accepts_valid_identity_and_preserves_audit_subject() {
    let caller =
        crate::Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
            .expect("valid identity should be accepted");
    assert_eq!(caller.subject(), Some("spiffe://apex/test"));
    assert_eq!(caller.bound_agent_id(), Some("agent"));
    assert!(caller.allows_scope("acme/prod"));
}

#[tokio::test]
async fn spawn_replay_worker_ticks_without_blocking_shutdown() {
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(OutboxedPublisher::new(
        InMemoryPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    )));
    let service = AuthenticatedGrpcService::new(adapter, OkVerifier);
    let handle = service.spawn_replay_worker(Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(40)).await;
    handle.abort();
    let _ = handle.await;
    let _ = bounded_event_ingest_server(service);
}

#[tokio::test]
async fn spawn_outbox_retention_worker_ticks_without_blocking_shutdown() {
    // InMemoryOutbox falls back to `EventOutbox::maintain`'s no-op default,
    // so this only proves the worker itself spawns, ticks on its own
    // schedule, and shuts down cleanly -- exactly the same guarantee
    // `spawn_replay_worker_ticks_without_blocking_shutdown` proves for the
    // replay worker. The FileOutbox test below proves an actual prune.
    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(OutboxedPublisher::new(
        InMemoryPublisher::default(),
        InMemoryOutbox::new(4).unwrap(),
    )));
    let service = AuthenticatedGrpcService::new(adapter, OkVerifier);
    let handle = service.spawn_outbox_retention_worker(Duration::from_millis(5), 0);
    tokio::time::sleep(Duration::from_millis(40)).await;
    handle.abort();
    let _ = handle.await;
    let _ = bounded_event_ingest_server(service);
}

#[tokio::test]
async fn spawn_outbox_retention_worker_prunes_completed_rows_and_frees_capacity() {
    // Regression test for FINDING #5: `EventOutbox::maintain` was fully
    // implemented and unit-tested but had no production call site, so a
    // durable outbox filled purely by settled (`complete`) history could
    // reach capacity and refuse every subsequent ingest with
    // `IDEMPOTENCY_CAPACITY`. This drives the fix through its real spawn
    // path (`AuthenticatedGrpcService::spawn_outbox_retention_worker`), not
    // just a direct call to `EventOutbox::maintain`.
    let base = std::env::temp_dir().join(format!(
        "apex-outbox-retention-worker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let path = base.join("events.jsonl");

    let first = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-0000000000a1",
        "acme",
        "prod",
        b"first-envelope".to_vec(),
    );
    let second = IngestRequest::new(
        "018f5c91-2d88-7c00-8000-0000000000a2",
        "acme",
        "prod",
        b"second-envelope".to_vec(),
    );

    // Capacity 1, filled entirely by one *completed* row: the capacity check
    // counts `complete` rows exactly like `pending` ones, so a never-swept
    // outbox refuses new ingest purely from settled history, matching the
    // finding.
    let mut outbox = FileOutbox::open(&path, &base, 1).unwrap();
    outbox.enqueue(&first).expect("seed pending");
    outbox
        .mark_complete(&OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: first.event_id().into(),
        })
        .unwrap();
    assert_eq!(
        outbox.enqueue(&second).unwrap_err().code,
        GatewayErrorCode::IdempotencyCapacity,
        "a completed-only outbox at capacity must still refuse new ingest before the sweep runs"
    );

    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::new(OutboxedPublisher::new(
        InMemoryPublisher::default(),
        outbox,
    )));
    let service = AuthenticatedGrpcService::new(adapter, OkVerifier);
    let handle = service.spawn_outbox_retention_worker(Duration::from_millis(5), 0);
    tokio::time::sleep(Duration::from_millis(80)).await;
    handle.abort();
    let _ = handle.await;
    // `spawn_blocking` cannot be cancelled by aborting the outer task, so
    // give an in-flight sweep a moment to finish before the last handle to
    // the journal file (owned inside `service`) is dropped below.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(service);

    // The maintenance task enters `spawn_blocking`; aborting its outer
    // scheduler handle cannot cancel that work. Retry the writer lock for a
    // bounded interval instead of relying on a fixed sleep that flakes on a
    // busy CI runner.
    let mut reopened = None;
    for _ in 0..200 {
        match FileOutbox::open(&path, &base, 1) {
            Ok(outbox) => {
                reopened = Some(outbox);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    let mut reopened = reopened.expect("retention worker must release the outbox lock");
    assert_eq!(
        reopened.enqueue(&second).unwrap(),
        EnqueueResult::Enqueued,
        "the sweep spawned by spawn_outbox_retention_worker must prune the completed row and free capacity"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn spawn_idempotency_retention_worker_prunes_committed_keys_and_frees_capacity() {
    let base = std::env::temp_dir().join(format!(
        "apex-idempotency-retention-worker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let path = base.join("idempotency.jsonl");
    let first = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000b1".into(),
    };
    let second = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000b2".into(),
    };

    let mut idempotency = FileIdempotencyStore::open(&path, &base, 1).unwrap();
    let reservation = match idempotency.reserve(first, [1; 32]).unwrap() {
        ReservationResult::Reserved(value) => value,
        other => panic!("unexpected reservation result: {other:?}"),
    };
    idempotency.commit(reservation).unwrap();
    assert_eq!(
        idempotency.reserve(second.clone(), [2; 32]).unwrap_err().code,
        GatewayErrorCode::IdempotencyCapacity
    );

    let adapter = AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
        InMemoryPublisher::default(),
        Box::new(idempotency),
    ));
    let service = AuthenticatedGrpcService::new(adapter, OkVerifier);
    let handle = service.spawn_idempotency_retention_worker(Duration::from_millis(5), 0);
    tokio::time::sleep(Duration::from_millis(80)).await;
    handle.abort();
    let _ = handle.await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(service);

    // `spawn_blocking` cannot be cancelled by aborting the outer task, so
    // retry the writer lock for a bounded interval instead of relying on a
    // fixed sleep that can be too short on a busy CI runner.
    let mut reopened = None;
    for _ in 0..200 {
        match FileIdempotencyStore::open(&path, &base, 1) {
            Ok(store) => {
                reopened = Some(store);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    let mut reopened = reopened.expect("retention worker must release the idempotency lock");
    assert!(matches!(
        reopened.reserve(second, [2; 32]).unwrap(),
        ReservationResult::Reserved(_)
    ));
    let _ = std::fs::remove_dir_all(&base);
}
