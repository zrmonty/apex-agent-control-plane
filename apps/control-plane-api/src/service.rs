//! The `ControlGateway` tonic service: authenticate the operator, validate
//! and canonicalize the command into a `control` event, and durably enqueue
//! it. Modeled on `apex_event_ingest`'s `AuthenticatedGrpcService`
//! (`apps/event-ingest/src/auth/service.rs`), but with its own independent
//! auth boundary and without any dependency on the ingest data path being
//! reachable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apex_event_ingest::{EphemeralStore, RateLimitKey};
use sha2::{Digest, Sha256};

use crate::auth::{OperatorCredentialResolver, OperatorTokenAuthenticator};
use crate::envelope::{ControlCommandInput, build_control_request};
use crate::errors::CommandError;
use crate::outbox::{ControlOutboxBackend, submit_command};
use crate::proto;

/// Admission rate limit applied per authenticated operator subject, after
/// auth succeeds. This is a separate control from
/// `OperatorTokenAuthenticator`'s auth-failure throttling: it bounds how
/// many *accepted-auth* commands a single operator identity can submit, so
/// a legitimate-but-compromised or malfunctioning operator credential
/// cannot flood the durable outbox.
pub(crate) const DEFAULT_MAX_COMMANDS_PER_WINDOW: u32 = 50;
pub(crate) const DEFAULT_ADMISSION_WINDOW: Duration = Duration::from_secs(1);
const MAX_TRACKED_OPERATORS: usize = 4096;

/// The `RateLimitKey.namespace` every control-gateway admission counter lives
/// under.
///
/// `apex_event_ingest`'s `ephemeral::types::KEY_PREFIX` is the fixed literal
/// `apex:ingest`, and this crate deliberately does not fork that module to
/// change it, so the *namespace component* is what separates the two services'
/// keyspaces. It is a value `event-ingest` can never produce for its own
/// admission counters: those use the envelope's `workspace_id` (or the literal
/// `unscoped`), and a workspace called `apex.control.admission` would have to
/// be created on purpose.
///
/// Belt and braces, because a shared keyspace is a cross-service isolation
/// failure and not merely untidy: the deployment profile additionally gives
/// this gateway its **own Valkey instance, own ACL user, and own client
/// certificate** (`deploy/compose/compose.control-valkey.yaml`), with the ACL
/// key pattern pinned to the hex encoding of this namespace. Same reasoning as
/// the separate NATS account and the separate Postgres database: every shared
/// infrastructure dependency this crate has gets its own distinct identity.
pub const CONTROL_ADMISSION_NAMESPACE: &str = "apex.control.admission";

/// The shared-store admission key for one operator subject.
///
/// The subject is hashed rather than interpolated. Two reasons, both real:
/// `ephemeral::types` hex-encodes each key component (doubling its length), so
/// a 256-byte subject would produce a 512-character key component; and an
/// operator subject is a Keycloak user identifier, which has no business being
/// written in clear into an explicitly non-authoritative accelerator that may
/// outlive the process and is evicted under `allkeys-lru`.
pub fn control_admission_rate_limit_key(subject: &str) -> RateLimitKey {
    RateLimitKey {
        namespace: CONTROL_ADMISSION_NAMESPACE.to_owned(),
        bucket: format!("op-{:x}", Sha256::digest(subject.as_bytes())),
    }
}

/// The optional cross-replica accelerator, in the shape `event-ingest`'s own
/// `AuthenticatedGrpcService` holds it.
pub type SharedEphemeralStore = Arc<Mutex<Box<dyn EphemeralStore>>>;

#[derive(Debug, Clone, Copy)]
struct AdmissionBucket {
    window_started: Instant,
    count: u32,
}

pub struct ControlGatewayService<R: OperatorCredentialResolver> {
    auth: Arc<OperatorTokenAuthenticator<R>>,
    outbox: Arc<ControlOutboxBackend>,
    admission: Mutex<HashMap<String, AdmissionBucket>>,
    /// Optional, non-authoritative, cross-replica admission counter. The
    /// process-local `admission` map above stays the hard floor whatever this
    /// does -- see [`ControlGatewayService::admit`].
    ephemeral: Option<SharedEphemeralStore>,
    limit: u32,
    window: Duration,
}

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    pub fn new(auth: OperatorTokenAuthenticator<R>, outbox: Arc<ControlOutboxBackend>) -> Self {
        Self {
            auth: Arc::new(auth),
            outbox,
            admission: Mutex::new(HashMap::new()),
            ephemeral: None,
            limit: DEFAULT_MAX_COMMANDS_PER_WINDOW,
            window: DEFAULT_ADMISSION_WINDOW,
        }
    }

    /// Attaches the cross-replica admission counter.
    ///
    /// Mirrors `apex_event_ingest::AuthenticatedGrpcService::with_ephemeral_store`
    /// exactly, including the "optional accelerator, local ceiling is the hard
    /// floor" contract: this store can only ever *deny* an admission that the
    /// local bucket would have allowed. It can never grant one.
    pub fn with_ephemeral_store(mut self, store: SharedEphemeralStore) -> Self {
        self.ephemeral = Some(store);
        self
    }

    /// Overrides the admission ceiling and window.
    ///
    /// Exists because the ceiling has to be observable to be provable: the
    /// live two-replica test bursts past it and asserts the *combined*
    /// admission across both replicas equals the configured ceiling rather
    /// than twice it, which is only a deterministic assertion when the window
    /// is long enough that the burst cannot straddle two of them.
    pub fn with_admission_limits(mut self, limit: u32, window: Duration) -> Self {
        self.limit = limit;
        self.window = window;
        self
    }

    /// Two ceilings, in this order.
    ///
    /// 1. The **shared** ceiling, when a store is attached. This is what makes
    ///    the limit mean the same thing at one replica and at N: without it,
    ///    N replicas admit N x `limit`, which is a real weakening of a control
    ///    that exists to stop a compromised operator credential flooding the
    ///    durable outbox.
    /// 2. The **process-local** ceiling, always. It is the hard floor: if the
    ///    accelerator is unreachable, misbehaving, or its lock is poisoned,
    ///    admission falls back to it rather than failing open. This is
    ///    `event-ingest`'s own pattern (`auth/service.rs::admit_request`
    ///    swallows the store's `Err` and lets the local buckets decide) and it
    ///    is deliberate: an *explicitly non-authoritative* accelerator must
    ///    never be able to take a control channel down with it, and must never
    ///    be able to authorise more than the local bucket would.
    ///
    /// The shared check runs on a blocking thread. `FallbackEphemeralStore`'s
    /// circuit breaker already bounds *how often* a dead accelerator is
    /// re-dialled -- it exists because the naive version stalled a live ingest
    /// for 135 seconds -- but one probe still costs a connect timeout plus DNS
    /// (measured at ~3.85s against Docker's resolver), and the store sits
    /// behind a single process-wide mutex. Running it on the tonic worker
    /// thread would hand that stall to every other in-flight request. This is
    /// the same reason `submit_command` already puts the outbox behind
    /// `spawn_blocking`.
    async fn admit(&self, subject: &str) -> Result<(), CommandError> {
        if let Some(store) = &self.ephemeral {
            let store = Arc::clone(store);
            let key = control_admission_rate_limit_key(subject);
            let limit = self.limit;
            let window = self.window;
            let shared = tokio::task::spawn_blocking(move || {
                let Ok(mut guard) = store.lock() else {
                    return None;
                };
                guard.check_rate_limit(&key, limit, window).ok()
            })
            .await
            .map_err(|_| CommandError::internal())?;
            if let Some(decision) = shared
                && !decision.allowed
            {
                return Err(CommandError::rate_limited());
            }
        }
        self.admit_locally(subject)
    }

    fn admit_locally(&self, subject: &str) -> Result<(), CommandError> {
        let Ok(mut buckets) = self.admission.lock() else {
            return Err(CommandError::internal());
        };
        let now = Instant::now();
        if !buckets.contains_key(subject) && buckets.len() >= MAX_TRACKED_OPERATORS {
            return Err(CommandError::rate_limited());
        }
        let bucket = buckets.entry(subject.to_owned()).or_insert(AdmissionBucket {
            window_started: now,
            count: 0,
        });
        if bucket.window_started.elapsed() >= self.window {
            *bucket = AdmissionBucket {
                window_started: now,
                count: 0,
            };
        }
        if bucket.count >= self.limit {
            return Err(CommandError::rate_limited());
        }
        bucket.count += 1;
        Ok(())
    }
}

pub fn bounded_control_gateway_server<R>(
    service: ControlGatewayService<R>,
) -> proto::control_gateway_server::ControlGatewayServer<ControlGatewayService<R>>
where
    R: OperatorCredentialResolver,
{
    proto::control_gateway_server::ControlGatewayServer::new(service)
        .max_decoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES)
}

#[tonic::async_trait]
impl<R: OperatorCredentialResolver> proto::control_gateway_server::ControlGateway
    for ControlGatewayService<R>
{
    async fn submit_command(
        &self,
        request: tonic::Request<proto::ControlCommandRequest>,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        // Independent auth boundary: never falls through to any ingest-path
        // credential, and failures here never touch the ingest rate-limit or
        // idempotency state.
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        self.admit(operator.subject())
            .await
            .map_err(CommandError::into_status)?;

        let input = ControlCommandInput::from_request(request.into_inner());
        let (command_id, ingest_request) =
            build_control_request(input, &operator).map_err(CommandError::into_status)?;

        let outbox = self.outbox.clone();
        let outcome = tokio::task::spawn_blocking(move || submit_command(&outbox, &ingest_request))
            .await
            .map_err(|_| CommandError::internal().into_status())?
            .map_err(CommandError::into_status)?;

        Ok(tonic::Response::new(proto::ControlCommandResponse {
            duplicate: outcome.duplicate,
            command_id,
            delivered: outcome.delivered,
        }))
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use apex_event_ingest::InMemoryOutbox;
    use prost_types::Struct as ProstStruct;

    use super::*;
    use crate::auth::{OperatorCaller, StaticOperatorTokenResolver};
    use crate::proto::control_gateway_server::ControlGateway as _;

    fn service() -> ControlGatewayService<StaticOperatorTokenResolver> {
        let resolver = StaticOperatorTokenResolver::new().with_token(
            "op-token",
            OperatorCaller::scoped("operator:zack", ["acme/prod"]).unwrap(),
        );
        let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> =
            Box::new(InMemoryOutbox::new(64).unwrap());
        ControlGatewayService::new(
            OperatorTokenAuthenticator::new(resolver),
            Arc::new(ControlOutboxBackend::new(outbox)),
        )
    }

    fn authed_request(body: proto::ControlCommandRequest) -> tonic::Request<proto::ControlCommandRequest> {
        let mut request = tonic::Request::new(body);
        request
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        request
    }

    /// A canonical lowercase UUIDv7 stamped with a recent millisecond, so it
    /// stays inside the gateway's `command_id` clock-acceptance window (see
    /// `envelope::command_millis_within_acceptance_window`). `suffix`
    /// distinguishes ids for tests that need several.
    ///
    /// The millisecond is captured once per test binary rather than read per
    /// call: idempotency tests submit the *same* id twice and must get the
    /// same string back, which a per-call clock read would not guarantee
    /// across a millisecond boundary.
    fn fresh_command_id(suffix: u64) -> String {
        static BASE_MILLIS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        let ms = *BASE_MILLIS.get_or_init(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
                & 0xFFFF_FFFF_FFFF
        });
        format!(
            "{:08x}-{:04x}-7000-8000-{:012x}",
            (ms >> 16) as u32,
            (ms & 0xFFFF) as u16,
            suffix & 0xFFFF_FFFF_FFFF
        )
    }

    fn stop_request() -> proto::ControlCommandRequest {
        proto::ControlCommandRequest {
            command_id: None,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: "agent-1".to_owned(),
            run_id: "run-1".to_owned(),
            parent_run_id: None,
            trace_id: "trace-1".to_owned(),
            action: proto::ControlAction::Stop as i32,
            reason_code: Some("operator.request".to_owned()),
            parameters: Some(ProstStruct::default()),
        }
    }

    #[tokio::test]
    async fn submit_command_accepts_a_well_formed_stop_command() {
        let service = service();
        let response = service
            .submit_command(authed_request(stop_request()))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.duplicate);
        assert!(!response.command_id.is_empty());
    }

    #[tokio::test]
    async fn submit_command_is_idempotent_for_a_repeated_command_id() {
        let service = service();
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(1));
        let first = service
            .submit_command(authed_request(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let second = service
            .submit_command(authed_request(request))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(first.command_id, second.command_id);
    }

    #[tokio::test]
    async fn submit_command_rejects_a_reused_command_id_with_different_fields() {
        let service = service();
        let mut first_request = stop_request();
        first_request.command_id = Some(fresh_command_id(2));
        service
            .submit_command(authed_request(first_request))
            .await
            .unwrap();

        let mut second_request = stop_request();
        second_request.command_id = Some(fresh_command_id(2));
        second_request.action = proto::ControlAction::Pause as i32; // different fields, same id.
        let status = service
            .submit_command(authed_request(second_request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn submit_command_rate_limits_a_single_operator_after_the_per_second_ceiling() {
        let service = service();
        for index in 0..DEFAULT_MAX_COMMANDS_PER_WINDOW {
            let mut request = stop_request();
            request.command_id = Some(fresh_command_id(u64::from(index)));
            service
                .submit_command(authed_request(request))
                .await
                .unwrap();
        }
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(0xffff_ffff));
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn submit_command_handles_concurrent_duplicate_submissions_without_a_torn_write() {
        let service = Arc::new(service());
        let command_id = fresh_command_id(0xab);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let service = service.clone();
            let mut request = stop_request();
            request.command_id = Some(command_id.clone());
            handles.push(tokio::spawn(async move {
                service.submit_command(authed_request(request)).await
            }));
        }
        let mut accepted_non_duplicate = 0;
        for handle in handles {
            let response = handle.await.unwrap().unwrap().into_inner();
            assert_eq!(response.command_id, command_id);
            if !response.duplicate {
                accepted_non_duplicate += 1;
            }
        }
        // Exactly one concurrent submission of the same command_id with the
        // same fields is the "first" acceptance; every other racer must see
        // it as a duplicate, never as a second independent enqueue.
        assert_eq!(accepted_non_duplicate, 1);
    }

    #[tokio::test]
    async fn submit_command_rejects_a_scope_the_operator_does_not_hold() {
        let service = service();
        let mut request = stop_request();
        request.workspace_id = "other-workspace".to_owned();
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn submit_command_rejects_missing_authentication() {
        let service = service();
        let request = tonic::Request::new(stop_request());
        let status = service.submit_command(request).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn submit_command_rejects_inject_without_untrusted_classification() {
        let service = service();
        let mut request = stop_request();
        request.action = proto::ControlAction::Inject as i32;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "content".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("hello".to_owned())),
            },
        );
        // Missing content_classification: "untrusted" -- must be rejected.
        request.parameters = Some(ProstStruct {
            fields: fields.into_iter().collect(),
        });
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    /// Two independent services sharing one `EphemeralStore`, which is what a
    /// two-replica deployment sharing one Valkey looks like from the admission
    /// path's point of view.
    fn replica_pair(
        limit: u32,
        store: Option<SharedEphemeralStore>,
    ) -> (
        ControlGatewayService<StaticOperatorTokenResolver>,
        ControlGatewayService<StaticOperatorTokenResolver>,
    ) {
        let build = || {
            let service =
                service().with_admission_limits(limit, std::time::Duration::from_secs(60));
            match &store {
                Some(store) => service.with_ephemeral_store(Arc::clone(store)),
                None => service,
            }
        };
        (build(), build())
    }

    async fn accepted_across(
        replicas: &(
            ControlGatewayService<StaticOperatorTokenResolver>,
            ControlGatewayService<StaticOperatorTokenResolver>,
        ),
        attempts: u64,
    ) -> usize {
        let mut accepted = 0;
        for index in 0..attempts {
            let mut request = stop_request();
            request.command_id = Some(fresh_command_id(0x5000 + index));
            let response = if index % 2 == 0 {
                replicas.0.submit_command(authed_request(request)).await
            } else {
                replicas.1.submit_command(authed_request(request)).await
            };
            if response.is_ok() {
                accepted += 1;
            }
        }
        accepted
    }

    /// The defect this closes. Two replicas with only process-local buckets
    /// admit twice the configured ceiling, which means the admission control
    /// added in the first pass quietly weakened the moment the Postgres outbox
    /// made multiple replicas safe to run.
    #[tokio::test]
    async fn two_replicas_without_a_shared_store_admit_twice_the_ceiling() {
        let replicas = replica_pair(8, None);
        assert_eq!(accepted_across(&replicas, 64).await, 16);
    }

    /// ... and with the shared store attached, the *combined* admission across
    /// both replicas is the configured ceiling, not twice it.
    #[tokio::test]
    async fn two_replicas_sharing_a_store_are_bounded_to_one_ceiling_between_them() {
        let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(
            apex_event_ingest::InMemoryEphemeralStore::new(),
        )));
        let replicas = replica_pair(8, Some(store));
        assert_eq!(accepted_across(&replicas, 64).await, 8);
    }

    /// An accelerator that answers `Unavailable` for everything must leave the
    /// process-local ceiling in charge -- neither failing open (admitting
    /// everything) nor failing shut (admitting nothing). This is the in-process
    /// half of the live Valkey-outage test.
    #[tokio::test]
    async fn a_dead_shared_store_falls_back_to_the_local_ceiling_rather_than_failing_open() {
        struct DeadStore;
        impl apex_event_ingest::EphemeralStore for DeadStore {
            fn check_rate_limit(
                &mut self,
                _key: &RateLimitKey,
                _limit: u32,
                _window: Duration,
            ) -> Result<apex_event_ingest::RateLimitDecision, apex_event_ingest::EphemeralError>
            {
                Err(apex_event_ingest::EphemeralError::unavailable())
            }
            fn increment_fingerprint(
                &mut self,
                _key: &apex_event_ingest::FingerprintCounterKey,
                _window: Duration,
            ) -> Result<u64, apex_event_ingest::EphemeralError> {
                Err(apex_event_ingest::EphemeralError::unavailable())
            }
            fn fingerprint_count(
                &mut self,
                _key: &apex_event_ingest::FingerprintCounterKey,
            ) -> Result<u64, apex_event_ingest::EphemeralError> {
                Err(apex_event_ingest::EphemeralError::unavailable())
            }
            fn set_deny_hint(
                &mut self,
                _key: &apex_event_ingest::DenyHintKey,
                _ttl: Duration,
            ) -> Result<(), apex_event_ingest::EphemeralError> {
                Err(apex_event_ingest::EphemeralError::unavailable())
            }
            fn is_denied(
                &mut self,
                _key: &apex_event_ingest::DenyHintKey,
            ) -> Result<bool, apex_event_ingest::EphemeralError> {
                Err(apex_event_ingest::EphemeralError::unavailable())
            }
        }
        let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(DeadStore)));
        let replicas = replica_pair(8, Some(store));
        // Each replica's own ceiling still applies: 8 + 8, never 64.
        assert_eq!(accepted_across(&replicas, 64).await, 16);
    }

    /// The shared store may only ever deny. A store that reports "allowed" for
    /// everything must not lift the process-local ceiling.
    #[tokio::test]
    async fn a_permissive_shared_store_cannot_raise_the_local_ceiling() {
        struct AlwaysAllow;
        impl apex_event_ingest::EphemeralStore for AlwaysAllow {
            fn check_rate_limit(
                &mut self,
                _key: &RateLimitKey,
                limit: u32,
                _window: Duration,
            ) -> Result<apex_event_ingest::RateLimitDecision, apex_event_ingest::EphemeralError>
            {
                Ok(apex_event_ingest::RateLimitDecision {
                    allowed: true,
                    remaining: limit,
                })
            }
            fn increment_fingerprint(
                &mut self,
                _key: &apex_event_ingest::FingerprintCounterKey,
                _window: Duration,
            ) -> Result<u64, apex_event_ingest::EphemeralError> {
                Ok(0)
            }
            fn fingerprint_count(
                &mut self,
                _key: &apex_event_ingest::FingerprintCounterKey,
            ) -> Result<u64, apex_event_ingest::EphemeralError> {
                Ok(0)
            }
            fn set_deny_hint(
                &mut self,
                _key: &apex_event_ingest::DenyHintKey,
                _ttl: Duration,
            ) -> Result<(), apex_event_ingest::EphemeralError> {
                Ok(())
            }
            fn is_denied(
                &mut self,
                _key: &apex_event_ingest::DenyHintKey,
            ) -> Result<bool, apex_event_ingest::EphemeralError> {
                Ok(false)
            }
        }
        let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(AlwaysAllow)));
        let replicas = replica_pair(8, Some(store));
        assert_eq!(accepted_across(&replicas, 64).await, 16);
    }

    /// The control gateway's admission counters must be unreachable from the
    /// ingest workload's keyspace. `event-ingest` keys its own admission
    /// bucket on the envelope's `workspace_id` (or `unscoped`); this namespace
    /// is a value it cannot produce without someone deliberately creating a
    /// workspace by that name, and the deployment profile pins the ACL key
    /// pattern to it as well.
    #[test]
    fn the_admission_key_is_namespaced_away_from_the_ingest_workload() {
        let key = control_admission_rate_limit_key("operator:keycloak:abc");
        assert_eq!(key.namespace, CONTROL_ADMISSION_NAMESPACE);
        assert_ne!(key.namespace, "unscoped");
        // The subject never appears in the key.
        assert!(!key.bucket.contains("operator"));
        assert!(!key.bucket.contains("abc"));
        // Distinct operators get distinct buckets; the same operator is stable.
        assert_ne!(
            control_admission_rate_limit_key("operator:keycloak:one").bucket,
            control_admission_rate_limit_key("operator:keycloak:two").bucket
        );
        assert_eq!(
            control_admission_rate_limit_key("operator:keycloak:one").bucket,
            control_admission_rate_limit_key("operator:keycloak:one").bucket
        );
        // Both components have to satisfy the store's own key grammar, or
        // every check_rate_limit call would fail InvalidKey and the shared
        // ceiling would silently never apply.
        let mut store = apex_event_ingest::InMemoryEphemeralStore::new();
        assert!(
            store
                .check_rate_limit(&key, 1, Duration::from_secs(1))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn submit_command_rejects_a_negative_budget_limit() {
        let service = service();
        let mut request = stop_request();
        request.action = proto::ControlAction::SetBudget as i32;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "budget_kind".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("tokens".to_owned())),
            },
        );
        fields.insert(
            "limit".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::NumberValue(-1.0)),
            },
        );
        request.parameters = Some(ProstStruct {
            fields: fields.into_iter().collect(),
        });
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}
