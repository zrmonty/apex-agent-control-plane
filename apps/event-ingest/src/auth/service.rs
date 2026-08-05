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
}

const MAX_BLOCKING_INGEST_TASKS: usize = 64;
const MAX_ADMISSION_REQUESTS_PER_SECOND: u32 = 256;
const MAX_ADMISSION_BYTES_PER_SECOND: u64 = 32 * 1024 * 1024;
const MAX_ADMISSION_SCOPES: usize = 4096;

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
        }
    }

    /// Attach a non-authoritative ephemeral store for cross-process rate limits.
    /// Local process buckets still enforce a hard ceiling when the accelerator
    /// is unavailable or disabled.
    pub fn with_ephemeral_store(mut self, store: Arc<Mutex<Box<dyn EphemeralStore>>>) -> Self {
        self.ephemeral = Some(store);
        self
    }

    fn admit_request(
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
            if let Ok(mut guard) = store.lock() {
                match guard.check_rate_limit(
                    &key,
                    MAX_ADMISSION_REQUESTS_PER_SECOND,
                    Duration::from_secs(1),
                ) {
                    Ok(decision) if !decision.allowed => {
                        return Err(GatewayError::new(GatewayErrorCode::RateLimited));
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        }

        let mut limits = self
            .admission_limits
            .lock()
            .map_err(|_| GatewayError::internal())?;
        let now = Instant::now();
        if !limits.contains_key(&scope) && limits.len() >= MAX_ADMISSION_SCOPES {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
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
        if let Err(error) = self.admit_request(&caller, request.get_ref()) {
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

    #[test]
    fn admit_request_isolates_buckets_by_identity_and_scope() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        assert!(service.admit_request(&caller, &envelope).is_ok());
        // A different scope for the same caller gets its own bucket.
        let other_scope_envelope = envelope_with_scope("acme", "staging");
        assert!(
            service
                .admit_request(&caller, &other_scope_envelope)
                .is_ok()
        );
    }

    #[test]
    fn admit_request_falls_back_to_a_shared_bucket_for_unsafe_scope_or_identity() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        // A control character in the scope must not smuggle its way into the
        // bucket key -- it collapses to the shared "__invalid_scope__"
        // bucket instead of being trusted verbatim.
        let unsafe_scope = envelope_with_scope("acme\u{1f}evil", "prod");
        assert!(service.admit_request(&caller, &unsafe_scope).is_ok());
        let no_scope = proto::EventEnvelope::default();
        assert!(service.admit_request(&caller, &no_scope).is_ok());
    }

    #[test]
    fn admit_request_rate_limits_after_the_local_ceiling() {
        let service = service();
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        for _ in 0..MAX_ADMISSION_REQUESTS_PER_SECOND {
            service.admit_request(&caller, &envelope).unwrap();
        }
        assert_eq!(
            service
                .admit_request(&caller, &envelope)
                .unwrap_err()
                .code,
            GatewayErrorCode::RateLimited
        );
    }

    #[test]
    fn admit_request_admits_normally_with_a_distributed_store_attached() {
        let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
            Arc::new(Mutex::new(Box::new(InMemoryEphemeralStore::new())));
        let service = service().with_ephemeral_store(store);
        let caller = Caller::authenticated("spiffe://apex/test", ["acme/prod"]);
        let envelope = envelope_with_scope("acme", "prod");
        // The distributed path must not prevent an otherwise-valid admission.
        assert!(service.admit_request(&caller, &envelope).is_ok());
    }

}
