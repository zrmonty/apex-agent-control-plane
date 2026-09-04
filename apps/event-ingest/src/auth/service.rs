#[path = "admission.rs"]
mod admission;
#[path = "grpc.rs"]
mod grpc;

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Semaphore;

use crate::{EphemeralStore, EventPublisher, SharedSecurityStore};
use apex_auth::CallerVerifier;

/// Phase 0.6 item 2b: admission is served by a POOL of N independent
/// `AuthenticatedIngestAdapter`s rather than a single one behind one mutex.
/// Each pool member owns its own idempotency/outbox connection(s) (Postgres:
/// N genuinely independent connections, so the database -- not an
/// in-process lock -- is what makes concurrent admission safe; file/memory:
/// forced to a single-member pool, see `startup::service::open_durability_stores`'s
/// doc comment on why N>1 would diverge for those backends).
///
/// `ingest` picks a starting slot via `next_adapter` (round-robin, so load
/// spreads evenly rather than always preferring slot 0) and then scans the
/// whole pool with `try_lock`: a request only reports `AdmissionBusy` when
/// EVERY slot is currently in use, not merely the one it happened to start
/// at. This is the direct generalization of the pre-pool single-adapter
/// `try_lock`-or-`AdmissionBusy` behavior -- `N == 1` reduces to exactly the
/// old behavior.
pub struct AuthenticatedGrpcService<P: EventPublisher, V: CallerVerifier> {
    adapters: Arc<Vec<Mutex<crate::AuthenticatedIngestAdapter<P>>>>,
    next_adapter: Arc<AtomicUsize>,
    /// A handle to the pool's combined Security Alert backend (see
    /// `SharedSecurityStore`), if one is configured -- shared by every pool
    /// member's `IngestGateway`. Signals recorded on the auth/admission
    /// error paths below go straight through this handle rather than
    /// `try_lock`ing a pool member, so a signal is never dropped just
    /// because every admission adapter happens to be busy at that instant.
    security_store: Option<SharedSecurityStore>,
    verifier: Arc<V>,
    blocking_limit: Arc<Semaphore>,
    admission_limits: Arc<Mutex<HashMap<String, AdmissionBucket>>>,
    /// Optional non-authoritative accelerator (Valkey or in-memory fallback).
    ephemeral: Option<Arc<Mutex<Box<dyn EphemeralStore>>>>,
    /// Bounds concurrent blocking-thread round trips into `ephemeral`. Says
    /// nothing about any individual scope's own budget -- saturation
    /// degrades to "no shared decision this attempt," never to a rejection.
    accelerator_slots: Arc<Semaphore>,
}

#[derive(Debug, Clone, Copy)]
struct AdmissionBucket {
    window_started: Instant,
    requests: u32,
    bytes: u64,
}

pub use grpc::bounded_event_ingest_server;

#[cfg(all(test, feature = "test-support"))]
use crate::{GatewayError, GatewayErrorCode, proto};
#[cfg(all(test, feature = "test-support"))]
use admission::{
    ADMISSION_BUCKET_RETENTION, MAX_ACCELERATOR_ADMISSION_OPERATIONS,
    MAX_ADMISSION_REQUESTS_PER_SECOND, MAX_ADMISSION_SCOPES,
};
#[cfg(all(test, feature = "test-support"))]
use grpc::{backlog_is_breached, backlog_should_alert, try_lock_pool};
#[cfg(all(test, feature = "test-support"))]
use std::sync::atomic::Ordering;
#[cfg(all(test, feature = "test-support"))]
use std::time::Duration;

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::{Caller, EphemeralStore, InMemoryEphemeralStore, InMemoryPublisher};

    struct NoopVerifier;
    impl CallerVerifier for NoopVerifier {
        fn verify(&self, _metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
            Err(GatewayError::unauthenticated())
        }
    }

    fn service() -> AuthenticatedGrpcService<InMemoryPublisher, NoopVerifier> {
        let gateway = crate::IngestGateway::new(InMemoryPublisher::default());
        let adapter = crate::AuthenticatedIngestAdapter::new(gateway);
        AuthenticatedGrpcService::new(adapter, NoopVerifier)
    }

    fn envelope_with_scope(workspace_id: &str, namespace_id: &str) -> proto::EventEnvelope {
        proto::EventEnvelope {
            scope: Some(proto::Scope {
                workspace_id: workspace_id.to_owned(),
                namespace_id: namespace_id.to_owned(),
                agent_group_ids: vec![],
            }),
            ..Default::default()
        }
    }

    fn adapter() -> crate::AuthenticatedIngestAdapter<InMemoryPublisher> {
        crate::AuthenticatedIngestAdapter::new(crate::IngestGateway::new(
            InMemoryPublisher::default(),
        ))
    }

    /// Phase 0.6 item 2b: `try_lock_pool` must reach every slot before
    /// reporting `AdmissionBusy`, not merely the round-robin starting slot.
    /// Holding real locks on two of three slots and confirming the third is
    /// still reachable is the direct N>1 generalization of the pre-pool
    /// single-adapter `try_lock`-or-busy test coverage.
    #[test]
    fn try_lock_pool_scans_every_slot_before_reporting_busy() {
        let adapters: Vec<Mutex<_>> = (0..3).map(|_| Mutex::new(adapter())).collect();
        let next = AtomicUsize::new(0);
        let _held_0 = adapters[0].lock().expect("uncontended test lock");
        let _held_1 = adapters[1].lock().expect("uncontended test lock");
        assert!(
            try_lock_pool(&adapters, &next).is_ok(),
            "slot 2 is free, so the pool must not report AdmissionBusy just \
             because slots 0 and 1 are held"
        );
    }

    /// The pool must report `AdmissionBusy` -- not silently wait, and not
    /// treat a subset of busy slots as the whole pool -- only once every
    /// single slot is simultaneously locked.
    #[test]
    fn try_lock_pool_reports_admission_busy_only_once_every_slot_is_locked() {
        let adapters: Vec<Mutex<_>> = (0..2).map(|_| Mutex::new(adapter())).collect();
        let next = AtomicUsize::new(0);
        let _held_0 = adapters[0].lock().expect("uncontended test lock");
        let _held_1 = adapters[1].lock().expect("uncontended test lock");
        match try_lock_pool(&adapters, &next) {
            Err(error) => assert_eq!(error.code, GatewayErrorCode::AdmissionBusy),
            Ok(_) => panic!("every slot is locked; the pool must not report success"),
        }
    }

    /// `next_adapter`'s round-robin start means consecutive calls do not
    /// pile onto the same slot when every slot is free.
    #[test]
    fn try_lock_pool_round_robins_the_starting_slot_across_calls() {
        let adapters: Vec<Mutex<_>> = (0..3).map(|_| Mutex::new(adapter())).collect();
        let next = AtomicUsize::new(0);
        let mut started_at = Vec::new();
        for _ in 0..3 {
            let before = next.load(Ordering::Relaxed) % adapters.len();
            let guard = try_lock_pool(&adapters, &next).expect("every slot is free");
            started_at.push(before);
            drop(guard);
        }
        assert_eq!(started_at, vec![0, 1, 2]);
    }

    /// A pool with no members can never admit anything -- `with_pool` must
    /// fail loudly (a construction-time bug) rather than silently building a
    /// service that reports `AdmissionBusy` forever.
    #[test]
    #[should_panic(expected = "at least one admission adapter")]
    fn with_pool_panics_on_an_empty_pool() {
        let _ = AuthenticatedGrpcService::<InMemoryPublisher, NoopVerifier>::with_pool(
            vec![],
            NoopVerifier,
        );
    }

    /// Every pool member built with a Security Alert backend must share the
    /// SAME backend (Phase 0.6 item 2b) -- otherwise findings recorded
    /// through one pool member would be invisible to a caller who lands on
    /// another. `with_pool` derives its shared handle from whichever member
    /// has one configured; this pins that it is reachable and that it is
    /// really shared (not a fresh, independent store per member).
    #[test]
    fn with_pool_shares_one_security_store_across_every_member() {
        let gateway_a = crate::IngestGateway::new(InMemoryPublisher::default())
            .with_security_store(8)
            .unwrap();
        let shared = gateway_a.shared_security_store().unwrap();
        let gateway_b = crate::IngestGateway::new(InMemoryPublisher::default())
            .with_shared_security_store(shared);
        let adapters = vec![
            crate::AuthenticatedIngestAdapter::new(gateway_a),
            crate::AuthenticatedIngestAdapter::new(gateway_b),
        ];
        let service = AuthenticatedGrpcService::with_pool(adapters, NoopVerifier);
        assert!(service.security_store.is_some());
        // A signal recorded through the service-level handle (as the real
        // `ingest` error paths do) must be visible through EITHER pool
        // member's gateway, proving they share one backend rather than two
        // independent ones.
        let mut envelope = envelope_with_scope("acme", "prod");
        envelope.event_id = "018f5c91-2d88-7c00-8000-000000000001".to_owned();
        service.record_security_signal(crate::SecuritySignal::AuthAbuse, &envelope);
        let caller = Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
            .expect("valid bound test caller");
        let found_via_member_1 = service.adapters[1]
            .lock()
            .expect("uncontended test lock")
            .gateway()
            .security_findings_for_scope(&caller, "acme", "prod")
            .unwrap()
            .unwrap();
        assert!(!found_via_member_1.is_empty());
    }

    #[tokio::test]
    async fn admit_request_isolates_buckets_by_identity_and_scope() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        assert!(service.admit_request(&caller, &envelope).await.is_ok());
        // A different scope for the same caller gets its own bucket.
        let other_scope_envelope = envelope_with_scope("acme", "staging");
        assert!(
            service
                .admit_request(&caller, &other_scope_envelope)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn admit_request_falls_back_to_a_shared_bucket_for_unsafe_scope_or_identity() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        // A control character in the scope must not smuggle its way into the
        // bucket key -- it collapses to the shared "__invalid_scope__"
        // bucket instead of being trusted verbatim.
        let unsafe_scope = envelope_with_scope("acme\u{1f}evil", "prod");
        assert!(service.admit_request(&caller, &unsafe_scope).await.is_ok());
        let no_scope = proto::EventEnvelope::default();
        assert!(service.admit_request(&caller, &no_scope).await.is_ok());
    }

    #[tokio::test]
    async fn admit_request_rate_limits_after_the_local_ceiling() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        for _ in 0..MAX_ADMISSION_REQUESTS_PER_SECOND {
            service.admit_request(&caller, &envelope).await.unwrap();
        }
        assert_eq!(
            service
                .admit_request(&caller, &envelope)
                .await
                .unwrap_err()
                .code,
            GatewayErrorCode::RateLimited
        );
    }

    #[tokio::test]
    async fn admit_request_admits_normally_with_a_distributed_store_attached() {
        let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
            Arc::new(Mutex::new(Box::new(InMemoryEphemeralStore::new())));
        let service = service().with_ephemeral_store(store);
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        // The distributed path must not prevent an otherwise-valid admission.
        assert!(service.admit_request(&caller, &envelope).await.is_ok());
    }

    /// Regression test for the unbounded, never-evicted `admission_limits`
    /// map (cross-tenant DoS): fill it to capacity with buckets whose
    /// window is already older than `ADMISSION_BUCKET_RETENTION`, then
    /// prove a brand-new scope is still admitted -- the retention pass must
    /// reclaim the stale entries before the capacity check runs, rather than
    /// permanently refusing every new scope once 4096 have ever been seen.
    #[tokio::test]
    async fn admit_request_evicts_stale_scopes_before_rejecting_a_new_one() {
        let service = service();
        {
            let mut limits = service.admission_limits.lock().expect("test bucket lock");
            for index in 0..MAX_ADMISSION_SCOPES {
                limits.insert(
                    format!("stale-{index}"),
                    AdmissionBucket {
                        window_started: Instant::now()
                            .checked_sub(ADMISSION_BUCKET_RETENTION + Duration::from_secs(1))
                            .expect("test duration underflow"),
                        requests: 0,
                        bytes: 0,
                    },
                );
            }
            assert_eq!(limits.len(), MAX_ADMISSION_SCOPES);
        }
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        assert!(
            service.admit_request(&caller, &envelope).await.is_ok(),
            "a new scope must be admitted once every existing bucket has aged out"
        );
        assert_eq!(
            service
                .admission_limits
                .lock()
                .expect("test bucket lock")
                .len(),
            1,
            "the retention pass must reclaim every stale bucket, not just make room for one"
        );
    }

    /// `accelerator_slots` bounds how many blocking-thread round trips into
    /// the shared store run at once; it says nothing about any individual
    /// scope's own admission. Saturating it must degrade to the local
    /// ceiling exactly like an unreachable or lock-poisoned store, not
    /// reject an admission the local ceiling would have allowed just
    /// because unrelated callers currently hold every permit. Mirrors
    /// control-plane-api's
    /// `a_saturated_accelerator_concurrency_limit_falls_back_to_the_local_ceiling_rather_than_failing_shut`.
    #[tokio::test]
    async fn admit_request_falls_back_to_the_local_ceiling_when_the_accelerator_concurrency_limit_is_saturated()
     {
        let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
            Arc::new(Mutex::new(Box::new(InMemoryEphemeralStore::new())));
        let service = service().with_ephemeral_store(store);
        // Hold every accelerator concurrency slot for the whole test,
        // without touching the process-local admission map at all.
        let _permits = service
            .accelerator_slots
            .clone()
            .try_acquire_many_owned(MAX_ACCELERATOR_ADMISSION_OPERATIONS as u32)
            .expect("nothing else has acquired a permit yet");
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        assert!(
            service.admit_request(&caller, &envelope).await.is_ok(),
            "admission within the local ceiling must succeed even while the \
             accelerator's concurrency limiter is saturated"
        );
    }

    #[test]
    fn backlog_is_breached_triggers_on_depth_alone() {
        assert!(backlog_is_breached(101, None, 100, 300_000));
        assert!(!backlog_is_breached(100, None, 100, 300_000));
        assert!(!backlog_is_breached(0, None, 100, 300_000));
    }

    #[test]
    fn backlog_is_breached_triggers_on_age_alone() {
        assert!(backlog_is_breached(0, Some(300_001), 100, 300_000));
        assert!(!backlog_is_breached(0, Some(300_000), 100, 300_000));
        assert!(!backlog_is_breached(0, None, 100, 300_000));
    }

    #[test]
    fn backlog_is_breached_is_an_or_not_an_and() {
        // Depth alone over threshold, age fine: still a breach.
        assert!(backlog_is_breached(101, Some(0), 100, 300_000));
        // Age alone over threshold, depth fine: still a breach.
        assert!(backlog_is_breached(0, Some(300_001), 100, 300_000));
    }

    #[test]
    fn backlog_should_alert_fires_on_the_crossing_into_breach() {
        // First tick of a fresh breach: always alert, regardless of the tick
        // counter (a freshly crossed breach must never wait out a cadence it
        // hasn't started yet).
        assert!(backlog_should_alert(true, false, 1, 20));
        assert!(backlog_should_alert(true, false, 0, 20));
    }

    #[test]
    fn backlog_should_alert_does_not_spam_every_tick_of_a_sustained_breach() {
        // Still breached, alerted last tick (counter reset to 0 then ticked
        // to 1): must not re-alert until the cadence elapses.
        assert!(!backlog_should_alert(true, true, 1, 20));
        assert!(!backlog_should_alert(true, true, 19, 20));
    }

    #[test]
    fn backlog_should_alert_re_alerts_at_the_bounded_cadence() {
        assert!(backlog_should_alert(true, true, 20, 20));
        assert!(backlog_should_alert(true, true, 21, 20));
    }

    #[test]
    fn backlog_should_alert_never_fires_once_the_breach_clears() {
        assert!(!backlog_should_alert(false, true, 1, 20));
        assert!(!backlog_should_alert(false, true, 20, 20));
        assert!(!backlog_should_alert(false, false, 0, 20));
    }
}
