//! The `ControlGateway` tonic service: authenticate the operator, validate
//! and canonicalize the command into a `control` event, and durably enqueue
//! it. Modeled on `apex_durability`'s `AuthenticatedGrpcService`
//! (`apps/event-ingest/src/auth/service.rs`), but with its own independent
//! auth boundary and without any dependency on the ingest data path being
//! reachable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apex_auth::{Caller, EphemeralStore, RateLimitKey};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::agent_auth::{
    AgentWorkloadAuthenticator, BoxedAgentWorkloadResolver, StaticAgentWorkloadResolver,
};
use crate::auth::{OperatorCredentialResolver, OperatorTokenAuthenticator};
use crate::dual_approval::DualApprovalGate;
use crate::errors::CommandError;
use crate::inbox::{ControlInboxBackend, DeliveryPolicy, InMemoryCommandInbox, ScopeAuthorizer};
use crate::outbox::ControlOutboxBackend;
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

/// Hard ceiling on how many targets one `SubmitBulkCommand` call may name.
///
/// **Flagged for the owner, chosen with the same discipline as
/// `MAX_COMMANDS_PER_POLL`/`MAX_AGENT_SCOPES`.** A bulk request's durable
/// writes are batched into one `spawn_blocking` task holding a single
/// `storage_slots` permit for the whole call (see
/// [`ControlGatewayService::submit_bulk_command`]), so its per-target outbox
/// commits and inbox records run strictly sequentially, each behind the same
/// mutexes every other in-flight `SubmitCommand`/`PollCommands`/`AckCommand`
/// call on this process is also waiting on. That makes one bulk call's worst
/// case hold time on shared storage roughly `targets.len()` times a single
/// `SubmitCommand`'s own. 64 matches `MAX_COMMANDS_PER_POLL`'s order of
/// magnitude: large enough that a real incident's target list clears it in
/// one call, small enough that the worst case stays comparable to a single
/// full poll batch rather than becoming its own denial-of-service surface. A
/// namespace with more targets than this issues a second call -- the ceiling
/// protects the shared gateway process, it is not an operational limit on how
/// many agents an incident can stop.
pub(crate) const MAX_BULK_COMMAND_TARGETS: usize = 64;

/// The `RateLimitKey.namespace` every control-gateway admission counter lives
/// under.
///
/// `apex_durability`'s `ephemeral::types::KEY_PREFIX` is the fixed literal
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
    /// The two-distinct-operator approval gate applied only to `force_stop`.
    /// See `dual_approval` for why this is process-local state and every
    /// other durability guarantee in this struct is unaffected by that.
    dual_approval: DualApprovalGate,
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
            dual_approval: DualApprovalGate::new(),
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
    /// Mirrors `apex_durability::AuthenticatedGrpcService::with_ephemeral_store`
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
    ///    accelerator is unreachable, misbehaving, its lock is poisoned, or
    ///    its own concurrency limiter (`accelerator_slots`, below) is
    ///    saturated, admission falls back to it rather than failing open --
    ///    or, in the saturated case, failing shut. This is `event-ingest`'s
    ///    own pattern (`auth/service.rs::admit_request` swallows the store's
    ///    `Err` and lets the local buckets decide) and it is deliberate: an
    ///    *explicitly non-authoritative* accelerator must never be able to
    ///    take a control channel down with it, and must never be able to
    ///    authorise more than the local bucket would.
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
            let shared = match self.accelerator_slots.clone().try_acquire_owned() {
                Ok(permit) => {
                    let store = Arc::clone(store);
                    let key = control_admission_rate_limit_key(subject);
                    let limit = self.limit;
                    let window = self.window;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let Ok(mut guard) = store.lock() else {
                            return None;
                        };
                        guard.check_rate_limit(&key, limit, window).ok()
                    })
                    .await
                    .map_err(|_| CommandError::internal())?
                }
                // `accelerator_slots` bounds concurrent blocking-thread
                // round trips into the accelerator; it says nothing about
                // `subject`. Treat exhaustion the same as an unreachable or
                // lock-poisoned store -- no decision, fall through to the
                // local floor -- rather than rejecting an admission the
                // local ceiling would have allowed just because unrelated
                // callers currently hold every permit.
                Err(_) => None,
            };
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
            let shared = match self.accelerator_slots.clone().try_acquire_owned() {
                Ok(permit) => {
                    let store = Arc::clone(store);
                    let key = control_poll_rate_limit_key(subject);
                    let limit = self.poll_limit;
                    let window = self.window;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let Ok(mut guard) = store.lock() else {
                            return None;
                        };
                        guard.check_rate_limit(&key, limit, window).ok()
                    })
                    .await
                    .map_err(|_| CommandError::internal())?
                }
                // Same degrade-to-local-floor reasoning as `admit` above.
                Err(_) => None,
            };
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

mod poll;
mod proto_mapping;
mod query;
mod submit;

/// Dispatch table only: each handler authenticates, validates, and mutates
/// state in its own module (`submit`, `poll`, `query`) as an inherent method
/// on [`ControlGatewayService`], grouped the way the RPCs themselves group --
/// the write path, the agent-facing path, and the operator query/management
/// path. This impl block has to stay a single, whole unit (Rust does not
/// allow one trait to be implemented for one type across more than one `impl`
/// block), so it is kept to one line per method to stay readable at this
/// size.
#[tonic::async_trait]
impl<R: OperatorCredentialResolver> proto::control_gateway_server::ControlGateway
    for ControlGatewayService<R>
{
    async fn submit_command(
        &self,
        request: tonic::Request<proto::ControlCommandRequest>,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        self.do_submit_command(request).await
    }

    /// Returns the commands pending for the **calling agent**. See
    /// `service::poll::ControlGatewayService::do_poll_commands` for the full
    /// security shape.
    async fn poll_commands(
        &self,
        request: tonic::Request<proto::PollCommandsRequest>,
    ) -> Result<tonic::Response<proto::PollCommandsResponse>, tonic::Status> {
        self.do_poll_commands(request).await
    }

    async fn ack_command(
        &self,
        request: tonic::Request<proto::AckCommandRequest>,
    ) -> Result<tonic::Response<proto::AckCommandResponse>, tonic::Status> {
        self.do_ack_command(request).await
    }

    async fn get_command_status(
        &self,
        request: tonic::Request<proto::GetCommandStatusRequest>,
    ) -> Result<tonic::Response<proto::GetCommandStatusResponse>, tonic::Status> {
        self.do_get_command_status(request).await
    }

    async fn list_commands(
        &self,
        request: tonic::Request<proto::ListCommandsRequest>,
    ) -> Result<tonic::Response<proto::ListCommandsResponse>, tonic::Status> {
        self.do_list_commands(request).await
    }

    /// Retracts a command an operator issued, before it has ever reached its
    /// target agent. See
    /// `service::query::ControlGatewayService::do_cancel_command` for the
    /// full behaviour.
    async fn cancel_command(
        &self,
        request: tonic::Request<proto::CancelCommandRequest>,
    ) -> Result<tonic::Response<proto::CancelCommandResponse>, tonic::Status> {
        self.do_cancel_command(request).await
    }

    async fn submit_bulk_command(
        &self,
        request: tonic::Request<proto::SubmitBulkCommandRequest>,
    ) -> Result<tonic::Response<proto::SubmitBulkCommandResponse>, tonic::Status> {
        self.do_submit_bulk_command(request).await
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
