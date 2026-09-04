use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(all(test, feature = "test-support"))]
use prost::Message;
use tokio::sync::Semaphore;

use super::grpc::{BACKLOG_RE_ALERT_TICKS, backlog_is_breached, backlog_should_alert};
use super::{AdmissionBucket, AuthenticatedGrpcService};
use crate::{
    BacklogObserver, Caller, EphemeralStore, EventPublisher, GatewayError, GatewayErrorCode,
    OutboxMaintainer, PendingEventReplayer, RateLimitKey, proto,
};
use apex_auth::CallerVerifier;

pub(super) const MAX_BLOCKING_INGEST_TASKS: usize = 64;
pub(super) const MAX_ADMISSION_REQUESTS_PER_SECOND: u32 = 256;
pub(super) const MAX_ADMISSION_BYTES_PER_SECOND: u64 = 32 * 1024 * 1024;
pub(super) const MAX_ADMISSION_SCOPES: usize = 4096;
// How long an idle (name, scope) admission bucket is kept before a `retain`
// pass reclaims it. Mirrors `verifier.rs`'s `AUTH_BUCKET_RETENTION`: these
// windows are ~1 second, so 60s is generous headroom while still bounding
// `admission_limits` to recently-active scopes instead of every scope ever
// seen by the process.
pub(super) const ADMISSION_BUCKET_RETENTION: Duration = Duration::from_secs(60);
// Same rationale and shape as control-plane-api's `MAX_ACCELERATOR_OPERATIONS`.
pub(super) const MAX_ACCELERATOR_ADMISSION_OPERATIONS: usize = 128;

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
    pub(super) fn record_security_signal(
        &self,
        signal: crate::SecuritySignal,
        envelope: &proto::EventEnvelope,
    ) {
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

    #[cfg(all(test, feature = "test-support"))]
    pub(super) async fn admit_request(
        &self,
        caller: &Caller,
        envelope: &proto::EventEnvelope,
    ) -> Result<(), GatewayError> {
        let encoded_len = envelope.encoded_len() as u64;
        self.admit_request_with_encoded_len(caller, envelope, encoded_len)
            .await
    }

    /// Admission's gRPC boundary already measured the decoded envelope before
    /// entering this path. Reusing that bounded size avoids a second protobuf
    /// traversal on every accepted request while preserving the two-argument
    /// helper used by direct tests and internal callers.
    pub(super) async fn admit_request_with_encoded_len(
        &self,
        caller: &Caller,
        envelope: &proto::EventEnvelope,
        encoded_len: u64,
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
        let bytes = encoded_len;

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
                let breached = backlog_is_breached(
                    depth,
                    oldest_pending_millis,
                    alert_depth,
                    alert_age_millis,
                );
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

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
