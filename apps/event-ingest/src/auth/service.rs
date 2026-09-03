use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use tokio::sync::Semaphore;

use apex_auth::{CallerVerifier, PeerIdentity};
use crate::{
    BacklogObserver, Caller, EphemeralStore, EventPublisher, GatewayError, GatewayErrorCode,
    MAX_ENVELOPE_BYTES, OutboxMaintainer, PendingEventReplayer, RateLimitKey,
    SharedSecurityStore, proto,
};

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
    /// Single-adapter constructor: a pool of exactly one, which is the
    /// pre-Phase-0.6-item-2b single-flight behavior. File/memory-backed
    /// deployments and every existing test still go through this path.
    pub fn new(adapter: crate::AuthenticatedIngestAdapter<P>, verifier: V) -> Self {
        Self::with_pool(vec![adapter], verifier)
    }

    /// Phase 0.6 item 2b: builds a service backed by a pool of `adapters.len()`
    /// independent admission adapters (see the struct-level doc comment).
    /// The pool's shared Security Alert backend, if any, is taken from
    /// whichever pool member has one configured -- `startup::service::run`
    /// gives every member the SAME `SharedSecurityStore` (via
    /// `IngestGateway::with_shared_security_store`), so any member is an
    /// equally valid source.
    ///
    /// # Panics
    /// Panics if `adapters` is empty -- a pool with no members can never
    /// admit anything and would silently degrade to permanent
    /// `AdmissionBusy`, which is a construction bug, not a runtime
    /// condition callers should have to handle.
    pub fn with_pool(adapters: Vec<crate::AuthenticatedIngestAdapter<P>>, verifier: V) -> Self {
        assert!(
            !adapters.is_empty(),
            "AuthenticatedGrpcService requires at least one admission adapter"
        );
        let security_store = adapters
            .iter()
            .find_map(|adapter| adapter.gateway().shared_security_store());
        Self {
            adapters: Arc::new(adapters.into_iter().map(Mutex::new).collect()),
            next_adapter: Arc::new(AtomicUsize::new(0)),
            security_store,
            verifier: Arc::new(verifier),
            blocking_limit: Arc::new(Semaphore::new(MAX_BLOCKING_INGEST_TASKS)),
            admission_limits: Arc::new(Mutex::new(HashMap::new())),
            ephemeral: None,
            accelerator_slots: Arc::new(Semaphore::new(MAX_ACCELERATOR_ADMISSION_OPERATIONS)),
        }
    }

    /// Records a redacted, best-effort Security Alert directly through the
    /// pool's shared backend (a no-op if none is configured), bypassing
    /// every per-adapter lock entirely. Used on the auth/admission error
    /// paths in `ingest` below, where the pre-pool code used to `try_lock`
    /// the single adapter and silently skip the write if it was busy --
    /// with a pool, "busy" no longer has to mean "skipped," since the
    /// backend is reachable without going through any adapter at all.
    fn record_security_signal(&self, signal: crate::SecuritySignal, envelope: &proto::EventEnvelope) {
        if let Some(store) = &self.security_store {
            store.record_rejected_envelope_signal(signal, envelope);
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
        // Pool member 0 only: the manual/fallback replay path, like every
        // background worker here, targets a single designated adapter
        // rather than the whole pool -- see the struct-level doc comment on
        // why index 0 is representative for Postgres (every pool member's
        // outbox connection sees the same underlying table) and is the
        // pool's only member for file/memory.
        let adapters = self.adapters.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let adapters = adapters.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut adapter = match adapters[0].try_lock() {
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

    /// Periodically prunes `complete` outbox rows outside the configured
    /// retention window and compacts the durable journal. Same shape as
    /// `spawn_replay_worker`: same locking (a busy adapter just skips this
    /// tick rather than blocking replay or a live request), same shutdown
    /// behavior (the caller aborts the returned handle), same error logging.
    ///
    /// Without this sweep running somewhere, `EventOutbox::maintain` is never
    /// called in production even though it is fully implemented: the outbox
    /// capacity check counts `complete` rows exactly like `pending` ones, so
    /// a long-running deployment eventually fills to capacity purely from
    /// settled history and starts refusing every new ingest with
    /// `IDEMPOTENCY_CAPACITY`.
    pub fn spawn_outbox_retention_worker(
        &self,
        interval: Duration,
        retention_millis: u64,
    ) -> tokio::task::JoinHandle<()>
    where
        P: OutboxMaintainer + Send + 'static,
        V: 'static,
    {
        // Pool member 0 only -- see `spawn_replay_worker`'s doc comment.
        let adapters = self.adapters.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let adapters = adapters.clone();
                let now_millis = now_unix_millis();
                let result = tokio::task::spawn_blocking(move || {
                    let mut adapter = match adapters[0].try_lock() {
                        Ok(adapter) => adapter,
                        // Never let a maintenance sweep wait behind a live
                        // admission, replay, or another sweep. The next
                        // interval retries.
                        Err(TryLockError::WouldBlock) => return Ok(()),
                        Err(TryLockError::Poisoned(_)) => {
                            return Err(GatewayError::internal());
                        }
                    };
                    catch_unwind(AssertUnwindSafe(|| {
                        adapter.maintain_outbox(now_millis, retention_millis)
                    }))
                    .map_err(|_| GatewayError::internal())?
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!(
                        "event-ingest outbox retention deferred: {}: {}",
                        error.code.public_code(),
                        error.summary
                    ),
                    Err(_) => eprintln!(
                        "event-ingest outbox retention deferred: INTERNAL_FAILURE: retention task failed"
                    ),
                }
            }
        })
    }

    /// Periodically prunes committed idempotency rows outside the configured
    /// retention window. Postgres stores share one table across pool members,
    /// while file/memory stores are forced to a single member, so one
    /// designated adapter is sufficient and avoids N duplicate sweeps.
    pub fn spawn_idempotency_retention_worker(
        &self,
        interval: Duration,
        retention_millis: u64,
    ) -> tokio::task::JoinHandle<()>
    where
        P: Send + 'static,
        V: 'static,
    {
        let adapters = self.adapters.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let adapters = adapters.clone();
                let now_millis = now_unix_millis();
                let result = tokio::task::spawn_blocking(move || {
                    let mut adapter = match adapters[0].try_lock() {
                        Ok(adapter) => adapter,
                        Err(TryLockError::WouldBlock) => return Ok(()),
                        Err(TryLockError::Poisoned(_)) => {
                            return Err(GatewayError::internal());
                        }
                    };
                    catch_unwind(AssertUnwindSafe(|| {
                        adapter.maintain_idempotency(now_millis, retention_millis)
                    }))
                    .map_err(|_| GatewayError::internal())?
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!(
                        "event-ingest idempotency retention deferred: {}: {}",
                        error.code.public_code(),
                        error.summary
                    ),
                    Err(_) => eprintln!(
                        "event-ingest idempotency retention deferred: INTERNAL_FAILURE: retention task failed"
                    ),
                }
            }
        })
    }

    /// Starts the Phase 0.6 item 6 backlog monitor: samples outbox depth and
    /// oldest-pending age every `interval` and, on a threshold breach, logs a
    /// structured operational warning and records a redacted operational
    /// Security Finding (see `SharedSecurityStore::record_backlog_alert` and the
    /// reserved `OPERATIONAL_WORKSPACE_ID`/`OPERATIONAL_NAMESPACE_ID` scope in
    /// `gateway/core.rs`).
    ///
    /// This is early-warning observability, one layer above the hard
    /// backpressure bound: Phase 0.6 item 5's outbox capacity ceiling already
    /// makes `enqueue` refuse admission with `IDEMPOTENCY_CAPACITY` once the
    /// outbox is full (`InMemoryOutbox`/`FileOutbox`/`PostgresOutbox::enqueue`
    /// all check capacity before inserting a new pending row), so the backlog
    /// can never grow unbounded regardless of whether this monitor is even
    /// running. This monitor exists so an operator finds out the backlog is
    /// degrading long before it reaches that ceiling -- nothing here changes
    /// an admission decision.
    ///
    /// Shape mirrors `spawn_outbox_retention_worker` exactly: interval loop,
    /// `spawn_blocking` + `try_lock` (a busy adapter just skips this tick),
    /// best-effort with every failure logged and swallowed. A sample or alert
    /// failure must never affect ingestion.
    ///
    /// Edge-triggered, not polled-and-spammed: a structured warning and a
    /// finding are recorded only when the backlog *newly* crosses into
    /// breach, or -- for a breach that never clears -- at most once every
    /// `BACKLOG_RE_ALERT_TICKS` ticks, so a stuck sink produces one alert per
    /// re-alert window instead of one every `interval`. See
    /// `backlog_should_alert`.
    pub fn spawn_backlog_monitor(
        &self,
        interval: Duration,
        alert_depth: u64,
        alert_age_millis: u64,
    ) -> tokio::task::JoinHandle<()>
    where
        P: BacklogObserver + Send + 'static,
        V: 'static,
    {
        // Sampling targets pool member 0 only -- see `spawn_replay_worker`'s
        // doc comment. Alert recording below goes straight through the
        // pool's shared security store instead (`self.security_store`),
        // bypassing per-adapter locking entirely.
        let adapters = self.adapters.clone();
        let security_store = self.security_store.clone();
        tokio::spawn(async move {
            let mut was_breached = false;
            let mut ticks_since_alert: u64 = 0;
            loop {
                tokio::time::sleep(interval).await;
                let sample_adapters = adapters.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut adapter = match sample_adapters[0].try_lock() {
                        Ok(adapter) => adapter,
                        // Never let a backlog sample wait behind a live
                        // admission, replay, or another sweep. The next
                        // interval retries.
                        Err(TryLockError::WouldBlock) => return Ok(None),
                        Err(TryLockError::Poisoned(_)) => {
                            return Err(GatewayError::internal());
                        }
                    };
                    catch_unwind(AssertUnwindSafe(|| adapter.backlog_stats()))
                        .map_err(|_| GatewayError::internal())?
                        .map(Some)
                })
                .await;
                let (depth, oldest_pending_millis) = match result {
                    Ok(Ok(Some(stats))) => stats,
                    // Adapter busy this tick: not a failure, just no sample.
                    Ok(Ok(None)) => continue,
                    Ok(Err(error)) => {
                        eprintln!(
                            "event-ingest backlog monitor deferred: {}: {}",
                            error.code.public_code(),
                            error.summary
                        );
                        continue;
                    }
                    Err(_) => {
                        eprintln!(
                            "event-ingest backlog monitor deferred: INTERNAL_FAILURE: monitor task failed"
                        );
                        continue;
                    }
                };
                let breached =
                    backlog_is_breached(depth, oldest_pending_millis, alert_depth, alert_age_millis);
                ticks_since_alert = ticks_since_alert.saturating_add(1);
                if backlog_should_alert(
                    breached,
                    was_breached,
                    ticks_since_alert,
                    BACKLOG_RE_ALERT_TICKS,
                ) {
                    eprintln!(
                        "event-ingest backlog WARNING: BACKLOG_THRESHOLD_EXCEEDED depth={depth} oldest_pending_ms={} alert_depth={alert_depth} alert_age_ms={alert_age_millis}",
                        oldest_pending_millis
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "unknown".to_owned())
                    );
                    // Best-effort: a failed or skipped finding write must
                    // never affect ingestion. Recorded directly through the
                    // shared security store rather than through any pool
                    // member's lock, so this can never be skipped just
                    // because every admission adapter happens to be busy --
                    // the structured `eprintln!` above already carries the
                    // operationally-actionable signal regardless of whether
                    // the finding lands.
                    if let Some(store) = &security_store {
                        let _ = catch_unwind(AssertUnwindSafe(|| {
                            store.record_backlog_alert(
                                depth,
                                oldest_pending_millis,
                                alert_depth,
                                alert_age_millis,
                            )
                        }));
                    }
                    ticks_since_alert = 0;
                }
                was_breached = breached;
            }
        })
    }
}

/// How many `spawn_backlog_monitor` ticks a still-breached backlog is
/// re-alerted at, once the initial threshold-crossing alert has already
/// fired. Twenty ticks (10 minutes at the default 30s interval) keeps a
/// stuck sink from being silent for hours while never approaching "an alert
/// every tick" -- see `backlog_should_alert`.
const BACKLOG_RE_ALERT_TICKS: u64 = 20;

/// Pure threshold decision: has the backlog crossed into a state worth
/// alerting on? Depth and age are independent triggers -- either one alone
/// is sufficient, matching the Phase 0.6 item 6 plan ("depth exceeds ...
/// OR age exceeds ..."). A `None` age (outbox currently empty) can never
/// itself breach the age threshold.
fn backlog_is_breached(
    depth: u64,
    oldest_pending_millis: Option<u64>,
    alert_depth: u64,
    alert_age_millis: u64,
) -> bool {
    depth > alert_depth || oldest_pending_millis.is_some_and(|age| age > alert_age_millis)
}

/// Pure edge/re-alert decision, independent of any adapter or clock so it is
/// directly unit-testable. Alerts on the transition into breach
/// (`!was_breached`), and otherwise at most once every `re_alert_cadence_ticks`
/// while the breach persists. A cleared breach (`!breached`) never alerts,
/// regardless of history.
fn backlog_should_alert(
    breached: bool,
    was_breached: bool,
    ticks_since_last_alert: u64,
    re_alert_cadence_ticks: u64,
) -> bool {
    breached && (!was_breached || ticks_since_last_alert >= re_alert_cadence_ticks)
}

/// Scans the pool starting at a round-robin index, returning the first slot
/// that is not currently locked. Returns `AdmissionBusy` only when every
/// slot in the pool is busy -- the direct N-way generalization of the
/// single-adapter `try_lock`-or-`AdmissionBusy` behavior this replaces
/// (`adapters.len() == 1` reduces to exactly the old behavior). A free
/// function, not a method on `AuthenticatedGrpcService`, because the only
/// call site (`ingest`'s `spawn_blocking` closure) must own `'static`
/// copies of `adapters`/`next_adapter` rather than borrowing `&self` across
/// the blocking-thread boundary.
fn try_lock_pool<'a, P: EventPublisher>(
    adapters: &'a [Mutex<crate::AuthenticatedIngestAdapter<P>>],
    next_adapter: &AtomicUsize,
) -> Result<std::sync::MutexGuard<'a, crate::AuthenticatedIngestAdapter<P>>, GatewayError> {
    let len = adapters.len();
    let start = next_adapter.fetch_add(1, Ordering::Relaxed) % len;
    for offset in 0..len {
        let index = (start + offset) % len;
        match adapters[index].try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => continue,
            // A poisoned adapter signals a prior panic that escaped the
            // `catch_unwind` around every call site that locks a pool
            // member -- a bug, not ordinary contention. Fail closed
            // immediately rather than silently skipping to another member,
            // matching the pre-pool single-adapter behavior.
            Err(TryLockError::Poisoned(_)) => return Err(GatewayError::internal()),
        }
    }
    Err(GatewayError::new(GatewayErrorCode::AdmissionBusy))
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
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
            self.record_security_signal(crate::SecuritySignal::AdmissionAbuse, request.get_ref());
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
                ) {
                    self.record_security_signal(
                        crate::SecuritySignal::AuthAbuse,
                        request.get_ref(),
                    );
                }
                return Err(error.grpc_status_value());
            }
            Err(_) => return Err(GatewayError::internal().grpc_status_value()),
        };
        if let Err(error) = self.admit_request(&caller, request.get_ref()).await {
            self.record_security_signal(crate::SecuritySignal::AdmissionAbuse, request.get_ref());
            return Err(error.grpc_status_value());
        }
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            self.blocking_limit.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            self.record_security_signal(crate::SecuritySignal::AdmissionAbuse, request.get_ref());
            GatewayError::new(GatewayErrorCode::RateLimited).grpc_status_value()
        })?
        .map_err(|_| GatewayError::internal().grpc_status_value())?;
        // Phase 0.6 item 2b: pick a pool slot via round-robin-then-scan
        // (`try_lock_pool`) rather than locking the single admission mutex
        // this replaces. `AdmissionBusy` is now only reported once every
        // slot in the pool is simultaneously in use, not merely the slot
        // this request happened to start at.
        let adapters = self.adapters.clone();
        let next_adapter = self.next_adapter.clone();
        let envelope = request.into_inner();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut adapter = try_lock_pool(&adapters, &next_adapter)?;
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
        let caller =
            Caller::authenticated_for_agent("spiffe://apex/test", "agent", ["acme/prod"])
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
