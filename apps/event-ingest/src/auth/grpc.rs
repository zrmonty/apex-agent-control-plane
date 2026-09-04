use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::Duration;

use super::AuthenticatedGrpcService;
use crate::{EventPublisher, GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES, proto};
use apex_auth::{CallerVerifier, PeerIdentity};
use prost::Message;

/// How many `spawn_backlog_monitor` ticks a still-breached backlog is
/// re-alerted at, once the initial threshold-crossing alert has already
/// fired. Twenty ticks (10 minutes at the default 30s interval) keeps a
/// stuck sink from being silent for hours while never approaching "an alert
/// every tick" -- see `backlog_should_alert`.
pub(super) const BACKLOG_RE_ALERT_TICKS: u64 = 20;

/// Pure threshold decision: has the backlog crossed into a state worth
/// alerting on? Depth and age are independent triggers -- either one alone
/// is sufficient, matching the Phase 0.6 item 6 plan ("depth exceeds ...
/// OR age exceeds ..."). A `None` age (outbox currently empty) can never
/// itself breach the age threshold.
pub(super) fn backlog_is_breached(
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
pub(super) fn backlog_should_alert(
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
pub(super) fn try_lock_pool<'a, P: EventPublisher>(
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
        let encoded_len = request.get_ref().encoded_len();
        if encoded_len > MAX_ENVELOPE_BYTES {
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
        if let Err(error) = self
            .admit_request_with_encoded_len(&caller, request.get_ref(), encoded_len as u64)
            .await
        {
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
