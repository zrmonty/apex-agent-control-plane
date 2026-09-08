use super::*;
use crate::{Caller, GatewayError, IngestGateway, IngestRequest, PublishOutcome};
use apex_durability::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "admission_readiness_auth_tests.rs"]
mod authentication;

struct Verifier {
    calls: Arc<AtomicUsize>,
    revoked: Arc<AtomicBool>,
}
impl CallerVerifier for Verifier {
    fn verify(&self, _: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        panic!("TLS verification required")
    }
    fn verify_with_peer(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.revoked.load(Ordering::SeqCst)
            || peer.map(|p| p.certificate_sha256) != Some([7; 32])
            || metadata.get("authorization").and_then(|v| v.to_str().ok())
                != Some("Bearer synthetic")
        {
            return Err(GatewayError::unauthenticated());
        }
        Caller::authenticated_for_agent("workload", "evidence", ["acme/prod"])
    }
}
struct Store;
impl EventPublisher for Store {
    fn publish(&mut self, _: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        panic!("no event")
    }
    fn check_admission_readiness(&mut self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }
}
impl IdempotencyStore for Store {
    fn reserve(
        &mut self,
        _: IdempotencyKey,
        _: [u8; 32],
    ) -> Result<ReservationResult, GatewayError> {
        panic!("no reservation")
    }
    fn commit(&mut self, _: IdempotencyReservation) -> Result<(), GatewayError> {
        panic!("no commit")
    }
    fn abort(&mut self, _: IdempotencyReservation) {
        panic!("no abort")
    }
    fn check_admission_readiness(&mut self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }
}
fn fixture() -> (
    AdmissionReadiness<Store, Verifier>,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let revoked = Arc::new(AtomicBool::new(false));
    let service = AuthenticatedGrpcService::new(
        AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
            Store,
            Box::new(Store),
        )),
        Verifier {
            calls: calls.clone(),
            revoked: revoked.clone(),
        },
    );
    (service.admission_readiness_service(), calls, revoked)
}
fn request() -> tonic::Request<proto::EvidenceAdmissionProbeRequest> {
    let mut request = tonic::Request::new(proto::EvidenceAdmissionProbeRequest {
        schema_version: 1,
        request_nonce: vec![3; 32],
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        agent_id: "evidence".into(),
    });
    request
        .metadata_mut()
        .insert("authorization", "Bearer synthetic".parse().unwrap());
    request
}
fn peer() -> PeerIdentity {
    PeerIdentity {
        certificate_sha256: [7; 32],
    }
}

#[tokio::test]
async fn readiness_echoes_exact_request_binding_only_after_rechecking_authentication() {
    let (service, calls, _) = fixture();
    let reply = service
        .check_peer(request(), peer())
        .await
        .unwrap()
        .into_inner();
    assert!(reply.ready);
    assert_eq!(reply.schema_version, 1);
    assert_eq!(reply.request_nonce, vec![3; 32]);
    assert_eq!(
        (
            reply.workspace_id.as_str(),
            reply.namespace_id.as_str(),
            reply.agent_id.as_str()
        ),
        ("acme", "prod", "evidence")
    );
    assert_eq!(reply.valid_for_us, 10000000);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn readiness_requires_actual_transport_peer_and_exact_bearer_binding() {
    use proto::evidence_admission_readiness_server::EvidenceAdmissionReadiness;
    let (service, _, _) = fixture();
    assert_eq!(
        service.check(request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        service
            .check_peer(
                request(),
                PeerIdentity {
                    certificate_sha256: [8; 32]
                }
            )
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

#[tokio::test]
async fn readiness_rejects_invalid_request_shape_and_cross_scope() {
    let (service, _, _) = fixture();
    let mut bad = request();
    bad.get_mut().request_nonce.pop();
    assert_eq!(
        service.check_peer(bad, peer()).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    let mut bad = request();
    bad.get_mut().agent_id = "other".into();
    assert_eq!(
        service.check_peer(bad, peer()).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

struct HeldStore {
    entered: Arc<AtomicUsize>,
    release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
}
impl IdempotencyStore for HeldStore {
    fn reserve(
        &mut self,
        _: IdempotencyKey,
        _: [u8; 32],
    ) -> Result<ReservationResult, GatewayError> {
        panic!("no reservation")
    }
    fn commit(&mut self, _: IdempotencyReservation) -> Result<(), GatewayError> {
        panic!("no commit")
    }
    fn abort(&mut self, _: IdempotencyReservation) {
        panic!("no abort")
    }
    fn check_admission_readiness(&mut self, _: &str, _: &str) -> Result<(), GatewayError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.release
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| GatewayError::internal())
    }
}
struct Release(std::sync::mpsc::Sender<()>);
impl Drop for Release {
    fn drop(&mut self) {
        for _ in 0..4 {
            let _ = self.0.send(());
        }
    }
}
type HeldFixture = (
    Arc<AdmissionReadiness<Store, Verifier>>,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    Release,
);
fn held() -> HeldFixture {
    let (tx, rx) = std::sync::mpsc::channel();
    let release = Arc::new(Mutex::new(rx));
    let entered = Arc::new(AtomicUsize::new(0));
    let revoked = Arc::new(AtomicBool::new(false));
    let adapters = (0..4)
        .map(|_| {
            AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
                Store,
                Box::new(HeldStore {
                    entered: entered.clone(),
                    release: release.clone(),
                }),
            ))
        })
        .collect();
    let service = AuthenticatedGrpcService::with_pool(
        adapters,
        Verifier {
            calls: Arc::new(AtomicUsize::new(0)),
            revoked: revoked.clone(),
        },
    );
    (
        Arc::new(service.admission_readiness_service()),
        entered,
        revoked,
        Release(tx),
    )
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn readiness_revalidates_revocation_after_storage_returns() {
    let (service, entered, revoked, release) = held();
    let owned = service.clone();
    let task = tokio::spawn(async move { owned.check_peer(request(), peer()).await });
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    revoked.store(true, Ordering::SeqCst);
    drop(release);
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(service.slots.available_permits(), 4);
}

#[tokio::test]
async fn readiness_timeout_retains_all_physical_work_slots_until_storage_returns() {
    let (service, entered, _, release) = held();
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let owned = service.clone();
            tokio::spawn(async move { owned.check_peer(request(), peer()).await })
        })
        .collect();
    until(|| entered.load(Ordering::SeqCst) == 4).await;
    assert_eq!(service.slots.available_permits(), 0);
    assert_eq!(
        service
            .check_peer(request(), peer())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    for task in tasks {
        assert_eq!(
            task.await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }
    assert_eq!(
        service.slots.available_permits(),
        0,
        "logical timeout is not physical closure"
    );
    drop(release);
    until(|| service.slots.available_permits() == 4).await;
}

#[tokio::test]
async fn readiness_request_cancellation_retains_its_physical_work_slot() {
    let (service, entered, _, release) = held();
    let owned = service.clone();
    let task = tokio::spawn(async move { owned.check_peer(request(), peer()).await });
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(service.slots.available_permits(), 3);
    drop(release);
    until(|| service.slots.available_permits() == 4).await;
}
