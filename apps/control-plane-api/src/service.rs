//! The `ControlGateway` tonic service: authenticate the operator, validate
//! and canonicalize the command into a `control` event, and durably enqueue
//! it. Modeled on `apex_event_ingest`'s `AuthenticatedGrpcService`
//! (`apps/event-ingest/src/auth/service.rs`), but with its own independent
//! auth boundary and without any dependency on the ingest data path being
//! reachable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apex_event_ingest::{Caller, EphemeralStore, RateLimitKey};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::agent_auth::{
    AgentWorkloadAuthenticator, BoxedAgentWorkloadResolver, StaticAgentWorkloadResolver,
    peer_identity_from_request,
};
use crate::auth::{OperatorCredentialResolver, OperatorTokenAuthenticator};
use crate::envelope::{AcceptedCommand, ControlCommandInput, build_control_request};
use crate::errors::CommandError;
use crate::inbox::{
    AckResult, CancelResult, ControlInboxBackend, DeliveryPolicy, DeliveryStatus,
    InMemoryCommandInbox, InboxKey, PendingCommand, PollTarget, RecordResult, ScopeAuthorizer,
};
use crate::outbox::{ControlOutboxBackend, submit_command};
use crate::proto;
use crate::status::GatewayRuntimeMetrics;

/// Admission rate limit applied per authenticated operator subject, after
/// auth succeeds. This is a separate control from
/// `OperatorTokenAuthenticator`'s auth-failure throttling: it bounds how
/// many *accepted-auth* commands a single operator identity can submit, so
/// a legitimate-but-compromised or malfunctioning operator credential
/// cannot flood the durable outbox.
pub(crate) const DEFAULT_MAX_COMMANDS_PER_WINDOW: u32 = 50;
pub(crate) const DEFAULT_ADMISSION_WINDOW: Duration = Duration::from_secs(1);
const MAX_TRACKED_OPERATORS: usize = 4096;
const MAX_STORAGE_OPERATIONS: usize = 64;
const MAX_ACCELERATOR_OPERATIONS: usize = 128;

/// Poll ceiling applied per authenticated *agent* identity, after auth
/// succeeds and independently of the operator ceiling above.
///
/// A separate control for a separate principal. Without it, one agent -- or
/// anything holding one agent's credential -- could poll in a tight loop and
/// spend the gateway's outbox mutex, its inbox mutex and its CPU on behalf of
/// every other agent on the same process. That is a denial of the one channel
/// ADR-0006 requires to stay reachable when everything else is degraded, which
/// makes it a security control rather than a capacity nicety.
///
/// **Flagged for the owner as a number this pass chose conservatively.** Five
/// polls per second per agent is roughly five times a sane 1-second cadence,
/// so a cooperative client with jitter and a retry never approaches it, while
/// a runaway client is bounded to something the gateway can absorb. The
/// response also carries `min_poll_interval_seconds` so a client does not have
/// to guess.
pub(crate) const DEFAULT_MAX_POLLS_PER_WINDOW: u32 = 5;
const MAX_TRACKED_AGENTS: usize = 8192;

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

/// The shared-store poll ceiling key for one agent workload subject.
///
/// Same namespace as the operator key above, a different bucket prefix.
/// Deliberately not a *new* namespace: `live-mtls/render_configs.py` derives
/// the control gateway's Valkey ACL key pattern from
/// [`CONTROL_ADMISSION_NAMESPACE`], and a second namespace would land outside
/// that pattern -- where every `check_rate_limit` call errors and the shared
/// ceiling silently stops applying, which is precisely the failure mode the
/// cross-replica pass already had to find the hard way. The `op-`/`poll-`
/// prefixes keep the two principals' counters disjoint within the one
/// namespace, and the subject is hashed for the same reasons it is above.
pub fn control_poll_rate_limit_key(subject: &str) -> RateLimitKey {
    RateLimitKey {
        namespace: CONTROL_ADMISSION_NAMESPACE.to_owned(),
        bucket: format!("poll-{:x}", Sha256::digest(subject.as_bytes())),
    }
}

/// Adapts an authenticated [`Caller`] to the inbox's scope question.
///
/// The only `ScopeAuthorizer` on the serving path. It holds no scope list of
/// its own: it forwards to `Caller::allows_scope`, so what an agent may read
/// is decided by the credential it presented and by nothing in the request.
struct CallerScopes<'caller>(&'caller Caller);

impl ScopeAuthorizer for CallerScopes<'_> {
    fn allows(&self, workspace_id: &str, namespace_id: &str) -> bool {
        self.0
            .allows_scope(&format!("{workspace_id}/{namespace_id}"))
    }
}

/// The optional cross-replica accelerator, in the shape `event-ingest`'s own
/// `AuthenticatedGrpcService` holds it.
pub type SharedEphemeralStore = Arc<Mutex<Box<dyn EphemeralStore>>>;

#[derive(Debug, Clone, Copy)]
struct AdmissionBucket {
    window_started: Instant,
    last_seen: Instant,
    count: u32,
}

pub struct ControlGatewayService<R: OperatorCredentialResolver> {
    auth: Arc<OperatorTokenAuthenticator<R>>,
    /// The *agent workload* credential boundary, entirely separate from
    /// `auth` above. Erased rather than a second generic parameter: a
    /// deployment picks one implementation at startup, and one dyn dispatch on
    /// the poll path is not worth propagating a type parameter through every
    /// caller and test.
    agent_auth: Arc<AgentWorkloadAuthenticator<BoxedAgentWorkloadResolver>>,
    outbox: Arc<ControlOutboxBackend>,
    /// Delivery state, the dimension the outbox structurally cannot track.
    inbox: Arc<ControlInboxBackend>,
    admission: Mutex<HashMap<String, AdmissionBucket>>,
    polls: Mutex<HashMap<String, AdmissionBucket>>,
    /// Optional, non-authoritative, cross-replica admission counter. The
    /// process-local `admission` map above stays the hard floor whatever this
    /// does -- see [`ControlGatewayService::admit`].
    ephemeral: Option<SharedEphemeralStore>,
    limit: u32,
    window: Duration,
    poll_limit: u32,
    delivery_policy: DeliveryPolicy,
    metrics: Arc<GatewayRuntimeMetrics>,
    storage_slots: Arc<Semaphore>,
    accelerator_slots: Arc<Semaphore>,
}

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    pub fn new(auth: OperatorTokenAuthenticator<R>, outbox: Arc<ControlOutboxBackend>) -> Self {
        Self::with_inbox(
            auth,
            outbox,
            Arc::new(ControlInboxBackend::new(Box::new(
                InMemoryCommandInbox::default(),
            ))),
        )
    }

    /// Constructs the service with an explicit durable inbox.
    ///
    /// [`Self::new`] defaults to an in-memory one so every existing embedding
    /// and test keeps working unchanged; the runnable binary always passes a
    /// durable backend, and `startup::service::run` is the only caller that
    /// matters for that guarantee.
    pub fn with_inbox(
        auth: OperatorTokenAuthenticator<R>,
        outbox: Arc<ControlOutboxBackend>,
        inbox: Arc<ControlInboxBackend>,
    ) -> Self {
        Self {
            auth: Arc::new(auth),
            // Fail-closed default: an empty static table authenticates no
            // agent at all, so a deployment that never configures agent
            // credentials serves `PollCommands` to nobody rather than to
            // everybody.
            agent_auth: Arc::new(AgentWorkloadAuthenticator::new(
                BoxedAgentWorkloadResolver::new(StaticAgentWorkloadResolver::new()),
            )),
            outbox,
            inbox,
            admission: Mutex::new(HashMap::new()),
            polls: Mutex::new(HashMap::new()),
            ephemeral: None,
            limit: DEFAULT_MAX_COMMANDS_PER_WINDOW,
            window: DEFAULT_ADMISSION_WINDOW,
            poll_limit: DEFAULT_MAX_POLLS_PER_WINDOW,
            delivery_policy: DeliveryPolicy::default(),
            metrics: Arc::new(GatewayRuntimeMetrics::default()),
            storage_slots: Arc::new(Semaphore::new(MAX_STORAGE_OPERATIONS)),
            accelerator_slots: Arc::new(Semaphore::new(MAX_ACCELERATOR_OPERATIONS)),
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<GatewayRuntimeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Installs the agent workload credential resolver used by
    /// `PollCommands`.
    pub fn with_agent_resolver(mut self, resolver: BoxedAgentWorkloadResolver) -> Self {
        self.agent_auth = Arc::new(AgentWorkloadAuthenticator::new(resolver));
        self
    }

    /// Overrides the per-agent poll ceiling and the delivery policy. Exists
    /// for the same reason `with_admission_limits` does: a ceiling and a
    /// redelivery window have to be observable to be provable.
    pub fn with_poll_limits(mut self, poll_limit: u32, policy: DeliveryPolicy) -> Self {
        self.poll_limit = poll_limit;
        self.delivery_policy = policy;
        self
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
            let permit = self
                .accelerator_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CommandError::rate_limited())?;
            let store = Arc::clone(store);
            let key = control_admission_rate_limit_key(subject);
            let limit = self.limit;
            let window = self.window;
            let shared = tokio::task::spawn_blocking(move || {
                let _permit = permit;
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
        admit_in(
            &self.admission,
            subject,
            self.limit,
            self.window,
            MAX_TRACKED_OPERATORS,
        )
    }

    /// The `PollCommands` equivalent of [`Self::admit`], keyed on the
    /// authenticated *agent* subject.
    ///
    /// Same two-ceiling shape and the same contract: the shared store may only
    /// ever deny, the process-local bucket is the hard floor, and an
    /// unreachable accelerator degrades to the local ceiling rather than
    /// failing open or shut. Keeping the structure identical is deliberate --
    /// a poll ceiling that behaved differently under an accelerator outage
    /// would be a second set of failure modes to reason about on the one
    /// channel that has to keep working when things are already bad.
    async fn admit_poll(&self, subject: &str) -> Result<(), CommandError> {
        if let Some(store) = &self.ephemeral {
            let permit = self
                .accelerator_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CommandError::rate_limited())?;
            let store = Arc::clone(store);
            let key = control_poll_rate_limit_key(subject);
            let limit = self.poll_limit;
            let window = self.window;
            let shared = tokio::task::spawn_blocking(move || {
                let _permit = permit;
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
        admit_in(
            &self.polls,
            subject,
            self.poll_limit,
            self.window,
            MAX_TRACKED_AGENTS,
        )
    }

    /// The interval a cooperative client should leave between polls, derived
    /// from the ceiling actually configured rather than hard-coded, so the two
    /// cannot drift.
    fn min_poll_interval_seconds(&self) -> u32 {
        let window = self.window.as_secs().max(1);
        let limit = u64::from(self.poll_limit.max(1));
        u32::try_from(window.div_ceil(limit)).unwrap_or(u32::MAX)
    }
}

/// One process-local fixed-window bucket map, shared by the operator
/// admission ceiling and the agent poll ceiling.
///
/// Factored out rather than duplicated because the two ceilings must agree on
/// the awkward parts: a poisoned lock fails closed rather than into an
/// unthrottled path, and a new identity is refused once the map is full rather
/// than evicting selectively -- selective eviction would let an attacker choose
/// whose bucket survives.
fn admit_in(
    buckets: &Mutex<HashMap<String, AdmissionBucket>>,
    subject: &str,
    limit: u32,
    window: Duration,
    max_tracked: usize,
) -> Result<(), CommandError> {
    let Ok(mut buckets) = buckets.lock() else {
        return Err(CommandError::internal());
    };
    let now = Instant::now();
    let stale_after = window.saturating_mul(2);
    buckets.retain(|_, bucket| now.duration_since(bucket.last_seen) < stale_after);
    if !buckets.contains_key(subject) && buckets.len() >= max_tracked {
        return Err(CommandError::rate_limited());
    }
    let bucket = buckets
        .entry(subject.to_owned())
        .or_insert(AdmissionBucket {
            window_started: now,
            last_seen: now,
            count: 0,
        });
    bucket.last_seen = now;
    if bucket.window_started.elapsed() >= window {
        *bucket = AdmissionBucket {
            window_started: now,
            last_seen: now,
            count: 0,
        };
    }
    if bucket.count >= limit {
        return Err(CommandError::rate_limited());
    }
    bucket.count += 1;
    Ok(())
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
        let AcceptedCommand {
            command_id,
            request: ingest_request,
            delivery,
        } = build_control_request(input, &operator).map_err(CommandError::into_status)?;

        let outbox = self.outbox.clone();
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let accept_result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            // Keep the authoritative outbox commit ahead of the delivery
            // record, but perform both synchronous backend operations in one
            // blocking task so the accept path pays one scheduler handoff.
            let outcome = submit_command(&outbox, &ingest_request)?;
            let delivery_result = inbox.with_lock(|inbox| inbox.record(&delivery))??;
            Ok::<_, CommandError>((outcome, delivery_result))
        })
        .await;
        let (outcome, delivery_result) = match accept_result {
            Ok(Ok(value)) => {
                self.metrics
                    .storage_healthy
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                value
            }
            Ok(Err(error)) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(error.into_status());
            }
            Err(_) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(CommandError::internal().into_status());
            }
        };

        self.metrics
            .submissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if outcome.duplicate {
            self.metrics
                .duplicate_submissions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Recorded *after* the outbox commits, and never conditionally on
        // whether the outbox call said "first acceptance" or "duplicate".
        //
        // Order matters: the outbox row is the authoritative durable
        // acceptance and the audit record, so it commits first. If this
        // second write then fails, the command is still durable and still
        // reaches the trace; the operator gets an error and retries the same
        // `command_id`, which the outbox recognises as a duplicate and which
        // reaches this line again -- and `record` is idempotent, so the retry
        // completes the delivery half without double-queueing it. Returning
        // success here on a failed inbox write is the one thing that would be
        // wrong: it is exactly the "recorded but never delivered" shape this
        // whole work item exists to remove.
        Ok(tonic::Response::new(proto::ControlCommandResponse {
            duplicate: outcome.duplicate,
            command_id,
            // A reused command_id whose outbox row is complete can still
            // create a fresh inbox delivery after retention. Describe that
            // delivery as pending rather than claiming the old trace fanout
            // covers it.
            delivered: outcome.delivered && delivery_result == RecordResult::AlreadyRecorded,
        }))
    }

    /// Returns the commands pending for the **calling agent**.
    ///
    /// The security shape of this method, in order:
    ///
    /// 1. The caller is authenticated against the agent workload credential
    ///    space (`agent_auth`), never the operator one. An operator token
    ///    cannot reach past this line.
    /// 2. The agent identity is `caller.bound_agent_id()` -- derived from the
    ///    credential. An unbound caller is refused outright rather than
    ///    defaulted to anything.
    /// 3. The permitted scopes are the caller's own, asked through
    ///    [`CallerScopes`].
    /// 4. The only request field read is `max_commands`, and it is clamped
    ///    into the gateway's own bounds. It can shorten a result set the
    ///    caller was already entitled to and nothing else.
    ///
    /// There is deliberately no branch anywhere below on an `agent_id`,
    /// `run_id`, `workspace_id` or `namespace_id` from the request, because
    /// the request has none. Adding one would be a security change.
    async fn poll_commands(
        &self,
        request: tonic::Request<proto::PollCommandsRequest>,
    ) -> Result<tonic::Response<proto::PollCommandsResponse>, tonic::Status> {
        let peer = peer_identity_from_request(&request);
        let caller = self
            .agent_auth
            .authenticate(request.metadata(), peer.as_ref())
            .map_err(CommandError::into_status)?;
        // `authenticated_for_agent` is the only public constructor an external
        // resolver can use and it always binds an agent id, so this is
        // belt-and-braces -- but an unbound caller reaching a per-agent
        // retrieval path is precisely the bug worth failing closed on rather
        // than assuming away.
        let Some(agent_id) = caller.bound_agent_id().map(str::to_owned) else {
            return Err(CommandError::unauthenticated().into_status());
        };
        let subject = caller.subject().unwrap_or(&agent_id).to_owned();
        self.admit_poll(&subject)
            .await
            .map_err(CommandError::into_status)?;

        let requested = request.get_ref().max_commands as usize;
        let limit = if requested == 0 {
            crate::inbox::DEFAULT_MAX_COMMANDS_PER_POLL
        } else {
            requested.min(crate::inbox::MAX_COMMANDS_PER_POLL)
        };
        let target = PollTarget {
            agent_id: agent_id.clone(),
            limit,
        };

        let inbox = self.inbox.clone();
        let policy = self.delivery_policy;
        let now_millis = crate::envelope::now_unix_millis();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        // `spawn_blocking` for the same reason the accept path uses it: the
        // inbox is behind a mutex, its durable backend performs synchronous
        // I/O, and neither may run on a tonic worker thread.
        let claim_result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox
                .with_lock(|inbox| inbox.claim(&target, &CallerScopes(&caller), policy, now_millis))
        })
        .await;
        let claimed: Vec<PendingCommand> = match claim_result {
            Ok(Ok(Ok(claimed))) => {
                self.metrics
                    .storage_healthy
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                claimed
            }
            Ok(Ok(Err(error))) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(error.into_status());
            }
            Ok(Err(error)) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(error.into_status());
            }
            Err(_) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(CommandError::internal().into_status());
            }
        };

        self.metrics
            .polls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(tonic::Response::new(proto::PollCommandsResponse {
            commands: claimed.into_iter().map(pending_to_proto).collect(),
            agent_id,
            min_poll_interval_seconds: self.min_poll_interval_seconds(),
        }))
    }

    async fn ack_command(
        &self,
        request: tonic::Request<proto::AckCommandRequest>,
    ) -> Result<tonic::Response<proto::AckCommandResponse>, tonic::Status> {
        let peer = peer_identity_from_request(&request);
        let caller = self
            .agent_auth
            .authenticate(request.metadata(), peer.as_ref())
            .map_err(CommandError::into_status)?;
        let Some(agent_id) = caller.bound_agent_id().map(str::to_owned) else {
            return Err(CommandError::unauthenticated().into_status());
        };
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
            || input.delivery_attempt == 0
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !caller.allows_scope(&format!("{}/{}", input.workspace_id, input.namespace_id)) {
            return Err(CommandError::scope_denied().into_status());
        }
        let target = PollTarget { agent_id, limit: 1 };
        let key = InboxKey {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            command_id: input.command_id.clone(),
        };
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let now_millis = crate::envelope::now_unix_millis();
        let result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.acknowledge(&target, &key, input.delivery_attempt, now_millis)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (acknowledged, already_acknowledged) = match result {
            AckResult::Acknowledged => (true, false),
            AckResult::AlreadyAcknowledged => (false, true),
            AckResult::NotFound => (false, false),
        };
        Ok(tonic::Response::new(proto::AckCommandResponse {
            command_id: input.command_id,
            acknowledged,
            already_acknowledged,
        }))
    }

    async fn get_command_status(
        &self,
        request: tonic::Request<proto::GetCommandStatusRequest>,
    ) -> Result<tonic::Response<proto::GetCommandStatusResponse>, tonic::Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }
        let key = InboxKey {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            command_id: input.command_id.clone(),
        };
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.status(&key, crate::DEFAULT_MAX_DELIVERY_ATTEMPTS)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (state, delivery_attempt) = result
            .map(|(status, attempt)| (delivery_status_to_proto(status), attempt))
            .unwrap_or((proto::CommandDeliveryState::Unspecified, 0));
        Ok(tonic::Response::new(proto::GetCommandStatusResponse {
            command_id: input.command_id,
            state: state as i32,
            delivery_attempt,
        }))
    }

    /// Retracts a command an operator issued, before it has ever reached its
    /// target agent.
    ///
    /// Authenticated and scope-checked identically to `get_command_status`
    /// above -- same operator credential space, same
    /// `operator.allows_scope(workspace_id, namespace_id)` gate, no agent
    /// identity involved. The only new behaviour is in the inbox: `cancel`
    /// refuses (rather than performs) the mutation once the command has been
    /// delivered even once, because at that point the agent may already be
    /// acting on it and retracting it would recreate exactly the "did the
    /// agent get it or not" ambiguity the delivery-tracking design in
    /// `inbox.rs` exists to eliminate.
    async fn cancel_command(
        &self,
        request: tonic::Request<proto::CancelCommandRequest>,
    ) -> Result<tonic::Response<proto::CancelCommandResponse>, tonic::Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }
        let key = InboxKey {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            command_id: input.command_id.clone(),
        };
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let now_millis = crate::envelope::now_unix_millis();
        let result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.cancel(&key, now_millis)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (cancelled, already_cancelled) = match result {
            CancelResult::Cancelled => (true, false),
            CancelResult::AlreadyCancelled => (false, true),
            CancelResult::NotFound => (false, false),
        };
        Ok(tonic::Response::new(proto::CancelCommandResponse {
            command_id: input.command_id,
            cancelled,
            already_cancelled,
        }))
    }
}

fn delivery_status_to_proto(status: DeliveryStatus) -> proto::CommandDeliveryState {
    match status {
        DeliveryStatus::Pending => proto::CommandDeliveryState::CommandDeliveryPending,
        DeliveryStatus::Delivered => proto::CommandDeliveryState::CommandDeliveryDelivered,
        DeliveryStatus::Acknowledged => proto::CommandDeliveryState::CommandDeliveryAcknowledged,
        DeliveryStatus::Exhausted => proto::CommandDeliveryState::CommandDeliveryExhausted,
        DeliveryStatus::Cancelled => proto::CommandDeliveryState::CommandDeliveryCancelled,
    }
}

/// Maps a stored delivery record onto the wire type.
///
/// `parameters` is decoded from the bytes recorded at accept time. A record
/// that somehow fails to decode yields `None` rather than an error: the
/// command's action, target and reason are what a `stop` needs, and refusing
/// to deliver a `stop` because an optional parameters blob is unreadable would
/// be the wrong trade on this channel.
fn pending_to_proto(command: PendingCommand) -> proto::PendingControlCommand {
    let action = match command.action.as_str() {
        "stop" => proto::ControlAction::Stop,
        "pause" => proto::ControlAction::Pause,
        "resume" => proto::ControlAction::Resume,
        "inject" => proto::ControlAction::Inject,
        "set_budget" => proto::ControlAction::SetBudget,
        _ => proto::ControlAction::Unspecified,
    };
    proto::PendingControlCommand {
        command_id: command.command_id,
        workspace_id: command.workspace_id,
        namespace_id: command.namespace_id,
        agent_id: command.agent_id,
        run_id: command.run_id,
        trace_id: command.trace_id,
        action: action as i32,
        reason_code: command.reason_code,
        parameters: if command.parameters.is_empty() {
            None
        } else {
            <prost_types::Struct as prost::Message>::decode(command.parameters.as_slice()).ok()
        },
        issued_at: command.issued_at,
        delivery_attempt: command.delivery_attempt,
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

    /// Certificate fingerprint fixture. `PeerIdentity` is a plain
    /// SHA-256-of-leaf value, so a test can construct one directly without a
    /// TLS session; the live tests in `tests/live_control_poll.rs` are what
    /// prove the real extraction path.
    fn peer(byte: u8) -> apex_event_ingest::PeerIdentity {
        apex_event_ingest::PeerIdentity {
            certificate_sha256: [byte; 32],
        }
    }

    fn hex32(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    /// A gateway serving one operator and two agent workloads in the same
    /// workspace/namespace, each with its own credential and its own pinned
    /// client certificate. This is the shape every isolation assertion below
    /// needs: same tenant, different agents, so a leak cannot be explained
    /// away by the scope check alone.
    fn service_with_two_agents() -> ControlGatewayService<StaticOperatorTokenResolver> {
        let agents = crate::agent_auth::parse_agent_token_table(&format!(
            "agent-a-token-abcdefgh|{}|agent-a|acme/prod;agent-b-token-abcdefgh|{}|agent-b|acme/prod",
            hex32(0xaa),
            hex32(0xbb)
        ))
        .expect("agent table must parse");
        service().with_agent_resolver(crate::agent_auth::BoxedAgentWorkloadResolver::new(agents))
    }

    fn poll_request(
        bearer: &str,
        peer: apex_event_ingest::PeerIdentity,
    ) -> tonic::Request<proto::PollCommandsRequest> {
        poll_request_for(bearer, peer, proto::PollCommandsRequest { max_commands: 0 })
    }

    fn poll_request_for(
        bearer: &str,
        peer: apex_event_ingest::PeerIdentity,
        body: proto::PollCommandsRequest,
    ) -> tonic::Request<proto::PollCommandsRequest> {
        let mut request = tonic::Request::new(body);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        // Stands in for what `peer_identity_from_request` reads off a real TLS
        // connection. The in-process service is not served over TLS, so the
        // extension has to be injected; `poll_commands` reads it through the
        // same function either way.
        request.extensions_mut().insert(peer);
        request
    }

    fn authed_request(
        body: proto::ControlCommandRequest,
    ) -> tonic::Request<proto::ControlCommandRequest> {
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

    // --- PollCommands ---------------------------------------------------

    async fn submit_stop_for(
        service: &ControlGatewayService<StaticOperatorTokenResolver>,
        agent_id: &str,
        suffix: u64,
    ) -> String {
        let mut request = stop_request();
        request.agent_id = agent_id.to_owned();
        request.command_id = Some(fresh_command_id(suffix));
        service
            .submit_command(authed_request(request))
            .await
            .expect("the operator must be able to submit")
            .into_inner()
            .command_id
    }

    #[tokio::test]
    async fn an_agent_retrieves_the_stop_command_issued_against_it() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x100).await;

        let response = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .expect("a registered agent must be able to poll")
            .into_inner();

        assert_eq!(response.agent_id, "agent-a");
        assert_eq!(response.commands.len(), 1);
        let command = &response.commands[0];
        assert_eq!(command.command_id, command_id);
        assert_eq!(command.action, proto::ControlAction::Stop as i32);
        assert_eq!(command.agent_id, "agent-a");
        assert_eq!(command.delivery_attempt, 1);
        assert!(!command.issued_at.is_empty());
        assert!(response.min_poll_interval_seconds >= 1);
    }

    #[tokio::test]
    async fn an_agent_acknowledges_a_delivery_and_retries_are_idempotent() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x101).await;
        let delivered = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        let command = &delivered.commands[0];

        let mut ack = tonic::Request::new(proto::AckCommandRequest {
            workspace_id: command.workspace_id.clone(),
            namespace_id: command.namespace_id.clone(),
            command_id: command.command_id.clone(),
            delivery_attempt: command.delivery_attempt,
        });
        ack.metadata_mut().insert(
            "authorization",
            "Bearer agent-a-token-abcdefgh".parse().unwrap(),
        );
        ack.extensions_mut().insert(peer(0xaa));
        let first = service.ack_command(ack).await.unwrap().into_inner();
        assert_eq!(first.command_id, command_id);
        assert!(first.acknowledged);
        assert!(!first.already_acknowledged);

        let empty = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert!(empty.commands.is_empty());

        let mut retry = tonic::Request::new(proto::AckCommandRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: command_id.clone(),
            delivery_attempt: 1,
        });
        retry.metadata_mut().insert(
            "authorization",
            "Bearer agent-a-token-abcdefgh".parse().unwrap(),
        );
        retry.extensions_mut().insert(peer(0xaa));
        let second = service.ack_command(retry).await.unwrap().into_inner();
        assert!(!second.acknowledged);
        assert!(second.already_acknowledged);

        let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id,
        });
        status
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        let status = service
            .get_command_status(status)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.state,
            proto::CommandDeliveryState::CommandDeliveryAcknowledged as i32
        );
        assert_eq!(status.delivery_attempt, 1);
    }

    #[tokio::test]
    async fn command_status_distinguishes_pending_and_delivered_and_rejects_wrong_agent_ack() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x102).await;

        let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: command_id.clone(),
        });
        status
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        let status = service
            .get_command_status(status)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.state,
            proto::CommandDeliveryState::CommandDeliveryPending as i32
        );
        assert_eq!(status.delivery_attempt, 0);

        let mut wrong_ack = tonic::Request::new(proto::AckCommandRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: command_id.clone(),
            delivery_attempt: 1,
        });
        wrong_ack.metadata_mut().insert(
            "authorization",
            "Bearer agent-b-token-abcdefgh".parse().unwrap(),
        );
        wrong_ack.extensions_mut().insert(peer(0xbb));
        let wrong_ack = service.ack_command(wrong_ack).await.unwrap().into_inner();
        assert!(!wrong_ack.acknowledged);
        assert!(!wrong_ack.already_acknowledged);

        let delivered = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(delivered.commands[0].delivery_attempt, 1);

        let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id,
        });
        status
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        let status = service
            .get_command_status(status)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.state,
            proto::CommandDeliveryState::CommandDeliveryDelivered as i32
        );
        assert_eq!(status.delivery_attempt, 1);
    }

    /// **The mandatory isolation test.** Agent B authenticates as itself and
    /// polls; a `stop` targeting agent A must not come back, and there must be
    /// no request field it could set to make it come back.
    ///
    /// The second half is the part a scope check alone would not prove: both
    /// agents hold `acme/prod`, so the only thing separating them is the
    /// server-derived bound agent identity.
    #[tokio::test]
    async fn an_agent_cannot_retrieve_another_agents_commands() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x200).await;

        // Agent B polls with its own valid credential and its own certificate.
        let response = service
            .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
            .await
            .expect("agent B is a legitimate caller")
            .into_inner();
        assert_eq!(response.agent_id, "agent-b");
        assert!(
            response.commands.is_empty(),
            "agent B retrieved a command targeting agent A: {:?}",
            response.commands
        );

        // ... and asking harder does not help: `max_commands` is the only
        // field on the request, and it can only narrow. There is no
        // agent_id/run_id/workspace selector to abuse -- which is the point,
        // and this assertion is here so that adding one is a test failure and
        // not a silent widening.
        let greedy = service
            .poll_commands(poll_request_for(
                "agent-b-token-abcdefgh",
                peer(0xbb),
                proto::PollCommandsRequest {
                    max_commands: u32::MAX,
                },
            ))
            .await
            .expect("a clamped max_commands must not be an error")
            .into_inner();
        assert!(greedy.commands.is_empty());

        // The command is still there for its actual target, so the emptiness
        // above is isolation and not the command having gone missing.
        let owner = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(owner.commands.len(), 1);
        assert_eq!(owner.commands[0].command_id, command_id);
    }

    /// Stealing agent A's bearer token is not enough: it is bound to agent A's
    /// client certificate, and agent B's connection presents a different one.
    #[tokio::test]
    async fn a_stolen_agent_token_is_useless_from_another_workload_connection() {
        let service = service_with_two_agents();
        submit_stop_for(&service, "agent-a", 0x300).await;
        let status = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xbb)))
            .await
            .expect_err("agent A's token from agent B's certificate must be refused");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    /// The operator credential space and the agent credential space are
    /// disjoint in both directions. An operator holds the authority to *issue*
    /// a stop, never the authority to read what is pending for an agent.
    #[tokio::test]
    async fn an_operator_credential_cannot_poll() {
        let service = service_with_two_agents();
        submit_stop_for(&service, "agent-a", 0x400).await;
        let status = service
            .poll_commands(poll_request("op-token", peer(0xaa)))
            .await
            .expect_err("an operator token must not authenticate on the poll path");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    /// ... and the reverse: an agent credential cannot submit a command.
    #[tokio::test]
    async fn an_agent_credential_cannot_submit_a_command() {
        let service = service_with_two_agents();
        let mut request = tonic::Request::new(stop_request());
        request.metadata_mut().insert(
            "authorization",
            "Bearer agent-a-token-abcdefgh".parse().unwrap(),
        );
        let status = service
            .submit_command(request)
            .await
            .expect_err("an agent credential must not authenticate on the submit path");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    /// A gateway that was never configured with agent credentials must serve
    /// `PollCommands` to nobody, not to everybody.
    #[tokio::test]
    async fn a_gateway_with_no_agent_credentials_authenticates_no_agent() {
        let service = service();
        let status = service
            .poll_commands(poll_request("anything-at-all-here", peer(0xaa)))
            .await
            .expect_err("an unconfigured agent credential space must fail closed");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    /// mTLS is load-bearing on this path, not decoration: a caller the
    /// transport did not give a client certificate for is refused before the
    /// token is even considered.
    #[tokio::test]
    async fn a_poll_with_no_client_certificate_is_refused() {
        let service = service_with_two_agents();
        let mut request = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
        request.metadata_mut().insert(
            "authorization",
            "Bearer agent-a-token-abcdefgh".parse().unwrap(),
        );
        let status = service
            .poll_commands(request)
            .await
            .expect_err("strict peer requirement must refuse a certificate-less caller");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    /// A command an agent has already retrieved is not handed to it again on
    /// the next poll, so a 1-second cadence does not re-enact a `stop` dozens
    /// of times. Redelivery after the window is covered in `inbox.rs`, where
    /// the clock is injectable.
    #[tokio::test]
    async fn a_retrieved_command_is_not_immediately_redelivered() {
        let service = service_with_two_agents();
        submit_stop_for(&service, "agent-a", 0x500).await;
        let first = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.commands.len(), 1);
        let second = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert!(second.commands.is_empty());
    }

    /// An agent polling aggressively must be bounded, or one workload can
    /// degrade the control channel for every other workload sharing the
    /// gateway.
    #[tokio::test]
    async fn poll_is_rate_limited_per_agent_after_the_ceiling() {
        let service = service_with_two_agents();
        for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
            service
                .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
                .await
                .expect("polls inside the ceiling must succeed");
        }
        let status = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .expect_err("the poll ceiling must be enforced");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);

        // ... and the ceiling is per agent: a second workload is unaffected by
        // the first one's behaviour, or one noisy agent becomes an outage for
        // everybody.
        service
            .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
            .await
            .expect("a different agent must have its own budget");
    }

    #[test]
    fn the_poll_rate_limit_key_is_disjoint_from_the_operator_one() {
        let subject = "spiffe://apex/workload/agent-a";
        let poll = control_poll_rate_limit_key(subject);
        let operator = control_admission_rate_limit_key(subject);
        // Same namespace on purpose (see the key function's own comment: a
        // second namespace would fall outside the deployment's Valkey ACL
        // pattern and the shared ceiling would silently stop applying) ...
        assert_eq!(poll.namespace, operator.namespace);
        // ... and disjoint buckets, so an agent's polls can never consume an
        // operator's command budget or vice versa.
        assert_ne!(poll.bucket, operator.bucket);
        assert!(!poll.bucket.contains("agent-a"));
        // Both must satisfy the store's own key grammar, or every
        // check_rate_limit call errors and the shared ceiling never applies.
        let mut store = apex_event_ingest::InMemoryEphemeralStore::new();
        assert!(
            store
                .check_rate_limit(&poll, 1, Duration::from_secs(1))
                .is_ok()
        );
    }

    /// The delivery record has to be written by the accept path, not by some
    /// later worker: a command accepted while the agent is offline must be
    /// waiting when it comes back.
    #[tokio::test]
    async fn a_command_accepted_before_the_agent_polls_is_waiting_for_it() {
        let service = service_with_two_agents();
        submit_stop_for(&service, "agent-a", 0x600).await;
        submit_stop_for(&service, "agent-a", 0x601).await;
        let response = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.commands.len(), 2);
    }

    /// An operator's idempotent resubmission must not queue a second delivery
    /// of the same command.
    #[tokio::test]
    async fn a_duplicate_submission_does_not_queue_a_second_delivery() {
        let service = service_with_two_agents();
        let mut request = stop_request();
        request.agent_id = "agent-a".to_owned();
        request.command_id = Some(fresh_command_id(0x700));
        service
            .submit_command(authed_request(request.clone()))
            .await
            .unwrap();
        service
            .submit_command(authed_request(request))
            .await
            .unwrap();
        let response = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.commands.len(), 1);
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

    // --- CancelCommand ----------------------------------------------------

    fn cancel_request(
        workspace_id: &str,
        namespace_id: &str,
        command_id: &str,
    ) -> tonic::Request<proto::CancelCommandRequest> {
        let mut request = tonic::Request::new(proto::CancelCommandRequest {
            workspace_id: workspace_id.to_owned(),
            namespace_id: namespace_id.to_owned(),
            command_id: command_id.to_owned(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        request
    }

    fn status_request(
        workspace_id: &str,
        namespace_id: &str,
        command_id: &str,
    ) -> tonic::Request<proto::GetCommandStatusRequest> {
        let mut request = tonic::Request::new(proto::GetCommandStatusRequest {
            workspace_id: workspace_id.to_owned(),
            namespace_id: namespace_id.to_owned(),
            command_id: command_id.to_owned(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        request
    }

    /// The success path: an undelivered command can be cancelled, a repeat
    /// cancellation is idempotent, and -- the property that actually matters
    /// -- the target agent never sees it on a subsequent poll.
    #[tokio::test]
    async fn cancel_command_of_an_undelivered_command_succeeds_and_it_is_never_polled() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x800).await;

        let first = service
            .cancel_command(cancel_request("acme", "prod", &command_id))
            .await
            .unwrap()
            .into_inner();
        assert!(first.cancelled);
        assert!(!first.already_cancelled);

        let second = service
            .cancel_command(cancel_request("acme", "prod", &command_id))
            .await
            .unwrap()
            .into_inner();
        assert!(!second.cancelled);
        assert!(second.already_cancelled);

        let polled = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert!(
            polled.commands.is_empty(),
            "a cancelled command must never be delivered to its agent"
        );

        let status = service
            .get_command_status(status_request("acme", "prod", &command_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.state,
            proto::CommandDeliveryState::CommandDeliveryCancelled as i32
        );
    }

    /// The refusal path: once a poll has handed a command to its agent even
    /// once, the gateway must not cancel it out from under that delivery.
    #[tokio::test]
    async fn cancel_command_of_an_already_delivered_command_is_refused() {
        let service = service_with_two_agents();
        let command_id = submit_stop_for(&service, "agent-a", 0x801).await;
        let delivered = service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(delivered.commands.len(), 1);

        let status = service
            .cancel_command(cancel_request("acme", "prod", &command_id))
            .await
            .expect_err("a delivered command must not be cancellable");
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);

        // Refused, not silently no-op'd: the command is still exactly as
        // delivered as it was, and a second poll after the redelivery window
        // must still be able to hand it back.
        let status = service
            .get_command_status(status_request("acme", "prod", &command_id))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.state,
            proto::CommandDeliveryState::CommandDeliveryDelivered as i32
        );
    }

    /// Mirrors `submit_command_rejects_a_scope_the_operator_does_not_hold`:
    /// an operator may only cancel within the workspace/namespace scopes its
    /// own credential holds, exactly the same gate `get_command_status`
    /// applies.
    #[tokio::test]
    async fn cancel_command_rejects_a_scope_the_operator_does_not_hold() {
        let service = service();
        let status = service
            .cancel_command(cancel_request(
                "other-workspace",
                "prod",
                &fresh_command_id(0x802),
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn cancel_command_of_an_unknown_command_id_reports_neither_flag_set() {
        let service = service();
        let response = service
            .cancel_command(cancel_request("acme", "prod", &fresh_command_id(0x803)))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.cancelled);
        assert!(!response.already_cancelled);
    }
}
