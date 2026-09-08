//! Physical authentication lifetime regressions at the real readiness boundary.
use super::*;
use std::sync::Condvar;

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
    entered: AtomicUsize,
}
impl Gate {
    fn hold(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let open = self.open.lock().unwrap();
        drop(self.changed.wait_while(open, |open| !*open).unwrap());
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

// A real thread releases even if a regression blocks the only async thread.
// Drop also releases on assertion failure, so held workers cannot hang teardown.
struct Watchdog {
    gate: Arc<Gate>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Watchdog {
    fn new(gate: Arc<Gate>) -> Self {
        let owned = gate.clone();
        let thread = std::thread::spawn(move || {
            let open = owned.open.lock().unwrap();
            let (mut open, _) = owned
                .changed
                .wait_timeout_while(open, Duration::from_secs(5), |open| !*open)
                .unwrap();
            *open = true;
            owned.changed.notify_all();
        });
        Self {
            gate,
            thread: Some(thread),
        }
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.gate.release();
        self.thread.take().unwrap().join().unwrap();
    }
}

struct HeldAuth {
    phase: usize,
    gate: Arc<Gate>,
    calls: [AtomicUsize; 8],
    changed_caller: AtomicBool,
}
impl CallerVerifier for HeldAuth {
    fn verify(&self, _: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        panic!("TLS verification required")
    }
    fn verify_with_peer(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        if peer.map(|p| p.certificate_sha256) != Some([7; 32])
            || metadata.get("authorization").and_then(|v| v.to_str().ok())
                != Some("Bearer synthetic")
            || metadata.get("x-original").and_then(|v| v.to_str().ok()) != Some("unchanged")
        {
            return Err(GatewayError::unauthenticated());
        }
        let index: usize = metadata
            .get("x-probe")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let call = self.calls[index].fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.phase {
            self.gate.hold();
        }
        let principal = if call == 2 && self.changed_caller.load(Ordering::SeqCst) {
            "changed"
        } else {
            "workload"
        };
        Caller::authenticated_for_agent(principal, "evidence", ["acme/prod"])
    }
}

struct ObservedStore(Arc<AtomicUsize>);
impl EventPublisher for ObservedStore {
    fn publish(&mut self, _: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        panic!("no event")
    }
    fn check_admission_readiness(&mut self, _: &str, _: &str) -> Result<(), GatewayError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn probe(index: usize) -> tonic::Request<proto::EvidenceAdmissionProbeRequest> {
    let mut request = request();
    request
        .metadata_mut()
        .insert("x-probe", index.to_string().parse().unwrap());
    request
        .metadata_mut()
        .insert("x-original", "unchanged".parse().unwrap());
    request
}

struct AuthFixture {
    service: Arc<AdmissionReadiness<ObservedStore, HeldAuth>>,
    observed: Arc<AtomicUsize>,
    watchdog: Watchdog,
}
fn held_auth(phase: usize) -> AuthFixture {
    let gate = Arc::new(Gate::default());
    let observed = Arc::new(AtomicUsize::new(0));
    let service = AuthenticatedGrpcService::with_pool(
        (0..4)
            .map(|_| {
                AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
                    ObservedStore(observed.clone()),
                    Box::new(Store),
                ))
            })
            .collect(),
        HeldAuth {
            phase,
            gate: gate.clone(),
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            changed_caller: AtomicBool::new(false),
        },
    );
    AuthFixture {
        service: Arc::new(service.admission_readiness_service()),
        observed,
        watchdog: Watchdog::new(gate),
    }
}

async fn held_auth_lifetime(phase: usize, abort: bool) {
    let fixture = held_auth(phase);
    let service = &fixture.service;
    let shared_capacity = service.blocking_limit.available_permits();
    let started = Instant::now();
    let tasks: Vec<_> = (0..4)
        .map(|index| {
            let owned = service.clone();
            tokio::spawn(async move { owned.check_peer(probe(index), peer()).await })
        })
        .collect();
    until(|| fixture.watchdog.gate.entered.load(Ordering::SeqCst) == 4).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "authentication blocked async polling"
    );
    if abort {
        for task in tasks {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    } else {
        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(3), task).await;
            assert_eq!(
                result.unwrap().unwrap().unwrap_err().code(),
                tonic::Code::Unavailable
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "authentication escaped the deadline"
        );
    }
    assert_eq!(service.slots.available_permits(), 0);
    assert_eq!(
        service.blocking_limit.available_permits(),
        shared_capacity - 4
    );
    assert!(
        service
            .adapters
            .iter()
            .all(|adapter| adapter.try_lock().is_ok()),
        "authentication must not retain an adapter lock"
    );
    for index in 4..8 {
        assert_eq!(
            service
                .check_peer(probe(index), peer())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(service.verifier.calls[index].load(Ordering::SeqCst), 0);
    }
    fixture.watchdog.gate.release();
    until(|| {
        service.slots.available_permits() == 4
            && service.blocking_limit.available_permits() == shared_capacity
    })
    .await;
    if !abort && phase == 1 {
        assert_eq!(
            fixture.observed.load(Ordering::SeqCst),
            0,
            "expired initial auth must not start storage"
        );
        for calls in &service.verifier.calls[..4] {
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "expired work must not start final auth"
            );
        }
    }
    assert!(
        service
            .check_peer(probe(4), peer())
            .await
            .unwrap()
            .into_inner()
            .ready
    );
    assert_eq!(service.verifier.calls[4].load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn held_initial_auth_timeout_retains_physical_permits() {
    held_auth_lifetime(1, false).await;
}

#[tokio::test]
async fn held_final_auth_timeout_retains_physical_permits() {
    held_auth_lifetime(2, false).await;
}

#[tokio::test]
async fn held_initial_auth_request_abort_retains_physical_permits() {
    held_auth_lifetime(1, true).await;
}

#[tokio::test]
async fn held_final_auth_request_abort_retains_physical_permits() {
    held_auth_lifetime(2, true).await;
}

#[tokio::test]
async fn expired_storage_does_not_start_final_authentication() {
    let (service, entered, _, release) = held();
    let owned = service.clone();
    let task = tokio::spawn(async move { owned.check_peer(request(), peer()).await });
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    drop(release);
    until(|| service.slots.available_permits() == 4).await;
    assert_eq!(service.verifier.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn final_authentication_preserves_binding_and_rejects_changed_caller() {
    let fixture = held_auth(2);
    let service = &fixture.service;
    let owned = service.clone();
    let task = tokio::spawn(async move { owned.check_peer(probe(0), peer()).await });
    until(|| fixture.watchdog.gate.entered.load(Ordering::SeqCst) == 1).await;
    service
        .verifier
        .changed_caller
        .store(true, Ordering::SeqCst);
    fixture.watchdog.gate.release();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(service.verifier.calls[0].load(Ordering::SeqCst), 2);
}

#[test]
fn expired_queued_worker_never_starts_initial_authentication() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture = held_auth(0);
        let service = &fixture.service;
        let gate = fixture.watchdog.gate.clone();
        let blocker = tokio::task::spawn_blocking(move || gate.hold());
        until(|| fixture.watchdog.gate.entered.load(Ordering::SeqCst) == 1).await;
        let shared_capacity = service.blocking_limit.available_permits();
        assert_eq!(
            service
                .check_peer(probe(0), peer())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            service.verifier.calls[0].load(Ordering::SeqCst),
            0,
            "queued work must not authenticate outside its worker"
        );
        assert_eq!(service.slots.available_permits(), 3);
        assert_eq!(
            service.blocking_limit.available_permits(),
            shared_capacity - 1
        );
        fixture.watchdog.gate.release();
        blocker.await.unwrap();
        until(|| {
            service.slots.available_permits() == 4
                && service.blocking_limit.available_permits() == shared_capacity
        })
        .await;
        assert_eq!(service.verifier.calls[0].load(Ordering::SeqCst), 0);
        assert_eq!(fixture.observed.load(Ordering::SeqCst), 0);
    });
}

#[tokio::test]
async fn held_final_auth_keeps_shared_capacity_unavailable_after_abort() {
    let fixture = held_auth(2);
    let service = &fixture.service;
    let other_work = service
        .blocking_limit
        .clone()
        .try_acquire_many_owned(63)
        .unwrap();
    let owned = service.clone();
    let started = Instant::now();
    let task = tokio::spawn(async move { owned.check_peer(probe(0), peer()).await });
    until(|| fixture.watchdog.gate.entered.load(Ordering::SeqCst) == 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "authentication blocked async polling"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(service.slots.available_permits(), 3);
    assert_eq!(service.blocking_limit.available_permits(), 0);
    assert_eq!(
        service
            .check_peer(probe(1), peer())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(service.verifier.calls[1].load(Ordering::SeqCst), 0);
    fixture.watchdog.gate.release();
    until(|| {
        service.slots.available_permits() == 4 && service.blocking_limit.available_permits() == 1
    })
    .await;
    assert!(
        service
            .check_peer(probe(1), peer())
            .await
            .unwrap()
            .into_inner()
            .ready
    );
    drop(other_work);
}
