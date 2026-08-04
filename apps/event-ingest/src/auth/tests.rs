use super::*;
use crate::outbox::{InMemoryOutbox, OutboxedPublisher};
use crate::{
    AuthenticatedIngestAdapter, InMemoryPublisher, IngestGateway, bounded_event_ingest_server,
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
