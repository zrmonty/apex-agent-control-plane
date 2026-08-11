use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::Semaphore;

use super::verifier::{CallerVerifier, PeerIdentity};
use crate::{
    Caller, EphemeralStore, EventPublisher, GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES,
    PendingEventReplayer, RateLimitKey, proto,
};

pub struct AuthenticatedGrpcService<P: EventPublisher, V: CallerVerifier> {
    adapter: Arc<Mutex<crate::AuthenticatedIngestAdapter<P>>>,
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

const MAX_BLOCKING_INGEST_TASKS: usize = 64;
const MAX_ADMISSION_REQUESTS_PER_SECOND: u32 = 256;
const MAX_ADMISSION_BYTES_PER_SECOND: u64 = 32 * 1024 * 1024;
const MAX_ADMISSION_SCOPES: usize = 4096;
// How long an idle (name, scope) admission bucket is kept before a `retain`
// pass reclaims it. Mirrors `verifier.rs`'s `AUTH_BUCKET_RETENTION`: these
// windows are ~1 second, so 60s is generous headroom while still bounding
// `admission_limits` to recently-active scopes instead of every scope ever
// seen by the process.
const ADMISSION_BUCKET_RETENTION: Duration = Duration::from_secs(60);
// Same rationale and shape as control-plane-api's `MAX_ACCELERATOR_OPERATIONS`.
const MAX_ACCELERATOR_ADMISSION_OPERATIONS: usize = 128;

#[derive(Debug, Clone, Copy)]
struct AdmissionBucket {
    window_started: Instant,
    requests: u32,
    bytes: u64,
}

impl<P: EventPublisher, V: CallerVerifier> AuthenticatedGrpcService<P, V> {
    pub fn new(adapter: crate::AuthenticatedIngestAdapter<P>, verifier: V) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            verifier: Arc::new(verifier),
            blocking_limit: Arc::new(Semaphore::new(MAX_BLOCKING_INGEST_TASKS)),
            admission_limits: Arc::new(Mutex::new(HashMap::new())),
            ephemeral: None,
            accelerator_slots: Arc::new(Semaphore::new(MAX_ACCELERATOR_ADMISSION_OPERATIONS)),
        }
    }

    /// Attach a non-authoritative ephemeral store for cross-process rate limits.
    /// Local process buckets still enforce a hard ceiling when the accelerator
    /// is unavailable or disabled.
    pub fn with_ephemeral_store(mut self, store: Arc<Mutex<Box<dyn EphemeralStore>>>) -> Self {
        self.ephemeral = Some(store);
        self
    }

    async fn admit_request(
        &self,
        caller: &Caller,
        envelope: &proto::EventEnvelope,
    ) -> Result<(), GatewayError> {
        let identity = caller
            .bound_agent_id()
            .or_else(|| caller.subject())
            .unwrap_or("authenticated");
        let identity =
            if identity.len() <= 256 && identity.is_ascii() && !identity.contains('\u{1f}') {
                identity
            } else {
                "__invalid_identity__"
            };
        let scope = envelope
            .scope
            .as_ref()
            .filter(|scope| {
                // Must reject the `\u{1f}` bucket delimiter (and any other
                // control byte), not just check length/ASCII — otherwise a
                // caller can smuggle the delimiter inside workspace_id or
                // namespace_id to alias its bucket key with another scope's.
                crate::is_scope_identifier(&scope.workspace_id)
                    && crate::is_scope_identifier(&scope.namespace_id)
            })
            .map(|scope| {
                format!(
                    "{}\u{1f}{}\u{1f}{}",
                    identity, scope.workspace_id, scope.namespace_id
                )
            })
            .unwrap_or_else(|| "__invalid_scope__".to_owned());
        let bytes = envelope.encoded_len() as u64;

        // Optional distributed rate limit (Valkey). Failures do not fail open:
        // process-local buckets below remain authoritative for this process.
        //
        // The check is a blocking socket round trip (≤3s command timeout,
        // ≤3s reconnect) behind a `std::sync::Mutex`, so it runs on a
        // `spawn_blocking` thread rather than directly on this request's
        // async task -- otherwise a few concurrent requests during a
        // sub-timeout Valkey degradation could occupy every Tokio worker
        // thread and stall the whole process. `accelerator_slots` bounds how
        // many such round trips run at once; it says nothing about this
        // scope's own admission, so exhaustion degrades to "no shared
        // decision this attempt" -- identical to an unreachable store or a
        // poisoned lock -- rather than rejecting an admission the local
        // ceiling below would otherwise allow. A panic inside the blocking
        // closure is a bug, not an accelerator-health signal, so (matching
        // control-plane-api's `admit`/`admit_poll`) that case alone is
        // surfaced as an internal error instead of being swallowed.
        if let Some(store) = &self.ephemeral {
            let namespace = envelope
                .scope
                .as_ref()
                .map(|scope| scope.workspace_id.as_str())
                .filter(|value| crate::is_scope_identifier(value))
                .unwrap_or("unscoped");
            let key = RateLimitKey {
                namespace: namespace.to_owned(),
                bucket: "admission".to_owned(),
            };
            let shared = match self.accelerator_slots.clone().try_acquire_owned() {
                Ok(permit) => {
                    let store = Arc::clone(store);
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let mut guard = store.lock().ok()?;
                        guard
                            .check_rate_limit(
                                &key,
                                MAX_ADMISSION_REQUESTS_PER_SECOND,
                                Duration::from_secs(1),
                            )
                            .ok()
                    })
                    .await
                    .map_err(|_| GatewayError::internal())?
                }
                Err(_) => None,
            };
            if let Some(decision) = shared
                && !decision.allowed
            {
                return Err(GatewayError::new(GatewayErrorCode::RateLimited));
            }
        }

        let mut limits = self
            .admission_limits
            .lock()
            .map_err(|_| GatewayError::internal())?;
        let now = Instant::now();
        // Evict idle buckets before the capacity check. Without this, once
        // MAX_ADMISSION_SCOPES distinct (identity, scope) pairs have ever
        // been seen, every new one is permanently rejected -- an
        // attacker-triggerable, cross-tenant denial of service that persists
        // until process restart. Mirrors `verifier.rs`'s `admit_attempt`.
        limits.retain(|_, bucket| bucket.window_started.elapsed() < ADMISSION_BUCKET_RETENTION);
        if !limits.contains_key(&scope) && limits.len() >= MAX_ADMISSION_SCOPES {
            // Still full after reclaiming idle entries: every tracked scope
            // is recently active. Evict the single oldest one rather than
            // refusing outright, exactly like `verifier.rs`'s equivalent
            // step (there, guarded by `in_flight == 0`; admission buckets
            // have no in-flight concept, so every entry is eligible).
            let eviction = limits
                .iter()
                .min_by_key(|(_, bucket)| bucket.window_started)
                .map(|(key, _)| key.clone());
            if let Some(eviction) = eviction {
                limits.remove(&eviction);
            } else {
                return Err(GatewayError::new(GatewayErrorCode::RateLimited));
            }
        }
        let bucket = limits.entry(scope).or_insert(AdmissionBucket {
            window_started: now,
            requests: 0,
            bytes: 0,
        });
        if bucket.window_started.elapsed() >= Duration::from_secs(1) {
            *bucket = AdmissionBucket {
                window_started: now,
                requests: 0,
                bytes: 0,
            };
        }
        if bucket.requests >= MAX_ADMISSION_REQUESTS_PER_SECOND
            || bucket.bytes.saturating_add(bytes) > MAX_ADMISSION_BYTES_PER_SECOND
        {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
        bucket.requests += 1;
        bucket.bytes = bucket.bytes.saturating_add(bytes);
        Ok(())
    }

    /// Starts a bounded replay loop for durable-outbox rows left pending by a
    /// failed fanout or process restart. Live requests continue to receive
    /// `IDEMPOTENCY_IN_PROGRESS` for an in-flight row; only this worker owns
    /// pending-row retries.
    pub fn spawn_replay_worker(&self, interval: Duration) -> tokio::task::JoinHandle<()>
    where
        P: PendingEventReplayer + Send + 'static,
        V: 'static,
    {
        let adapter = self.adapter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let adapter = adapter.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut adapter = match adapter.try_lock() {
                        Ok(adapter) => adapter,
                        // Never let a backlog replay wait behind a live
                        // admission or make the hot path wait behind replay.
                        // The next interval will retry the pending rows.
                        Err(TryLockError::WouldBlock) => return Ok(()),
                        Err(TryLockError::Poisoned(_)) => {
                            return Err(GatewayError::internal());
                        }
                    };
                    catch_unwind(AssertUnwindSafe(|| adapter.replay_pending()))
                        .map_err(|_| GatewayError::internal())?
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!(
                        "event-ingest outbox replay deferred: {}: {}",
                        error.code.public_code(),
                        error.summary
                    ),
                    Err(_) => eprintln!(
                        "event-ingest outbox replay deferred: INTERNAL_FAILURE: replay task failed"
                    ),
                }
            }
        })
    }
}

pub fn bounded_event_ingest_server<P, V>(
    service: AuthenticatedGrpcService<P, V>,
) -> proto::event_ingest_server::EventIngestServer<AuthenticatedGrpcService<P, V>>
where
    P: EventPublisher + Send + 'static,
    V: CallerVerifier,
{
    proto::event_ingest_server::EventIngestServer::new(service)
        .max_decoding_message_size(MAX_ENVELOPE_BYTES)
}

#[tonic::async_trait]
impl<P, V> proto::event_ingest_server::EventIngest for AuthenticatedGrpcService<P, V>
where
    P: EventPublisher + Send + 'static,
    V: CallerVerifier,
{
    async fn ingest(
        &self,
        request: tonic::Request<proto::EventEnvelope>,
    ) -> Result<tonic::Response<proto::IngestResponse>, tonic::Status> {
        if request.get_ref().encoded_len() > MAX_ENVELOPE_BYTES {
            if let Ok(mut adapter) = self.adapter.try_lock() {
                adapter.record_security_signal(
                    crate::SecuritySignal::AdmissionAbuse,
                    request.get_ref(),
                );
            }
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge).grpc_status_value());
        }
        let caller = match catch_unwind(AssertUnwindSafe(|| {
            let peer = PeerIdentity::from_request(&request);
            self.verifier
                .verify_with_peer(request.metadata(), peer.as_ref())
        })) {
            Ok(Ok(caller)) => caller,
            Ok(Err(error)) => {
                if matches!(
                    error.code,
                    GatewayErrorCode::Unauthenticated
                        | GatewayErrorCode::InvalidAuthorization
                        | GatewayErrorCode::RateLimited
                ) && let Ok(mut adapter) = self.adapter.try_lock()
                {
                    adapter.record_security_signal(
                        crate::SecuritySignal::AuthAbuse,
                        request.get_ref(),
                    );
                }
                return Err(error.grpc_status_value());
            }
            Err(_) => return Err(GatewayError::internal().grpc_status_value()),
        };
        if let Err(error) = self.admit_request(&caller, request.get_ref()).await {
            if let Ok(mut adapter) = self.adapter.try_lock() {
                adapter.record_security_signal(
                    crate::SecuritySignal::AdmissionAbuse,
                    request.get_ref(),
                );
            }
            return Err(error.grpc_status_value());
        }
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            self.blocking_limit.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            if let Ok(mut adapter) = self.adapter.try_lock() {
                adapter.record_security_signal(
                    crate::SecuritySignal::AdmissionAbuse,
                    request.get_ref(),
                );
            }
            GatewayError::new(GatewayErrorCode::RateLimited).grpc_status_value()
        })?
        .map_err(|_| GatewayError::internal().grpc_status_value())?;
        let adapter = self.adapter.clone();
        let envelope = request.into_inner();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut adapter = match adapter.try_lock() {
                Ok(adapter) => adapter,
                Err(TryLockError::WouldBlock) => {
                    return Err(GatewayError::new(GatewayErrorCode::AdmissionBusy));
                }
                Err(TryLockError::Poisoned(_)) => return Err(GatewayError::internal()),
            };
            catch_unwind(AssertUnwindSafe(|| {
                adapter.ingest_envelope(&caller, envelope)
            }))
            .map_err(|_| GatewayError::internal())?
        })
        .await
        .map_err(|_| GatewayError::internal().grpc_status_value())?
        .map(tonic::Response::new)
        .map_err(|error| error.grpc_status_value())
    }
}

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
}
