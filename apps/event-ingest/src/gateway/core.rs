use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use prost::Message;
use sha2::{Digest, Sha256};

use super::IngestOutcome;
use crate::outbox::{BacklogObserver, OutboxMaintainer, PendingEventReplayer};
use crate::{
    GatewayError, GatewayErrorCode,
    idempotency::{IdempotencyKey, IdempotencyStore, InMemoryIdempotencyStore, ReservationResult},
    persistence::FindingJournal,
    proto,
    security::{
        DetectionInput, FindingError, FindingStore, SecurityFinding, SecuritySignal,
        detect_and_record,
    },
    validation::{Caller, IngestRequest, is_lowercase_uuidv7, is_scope_identifier},
};
use apex_durability::{EventPublisher, PublishOutcome};

/// Reserved operational scope for Phase 0.6 item 6's outbox backlog alerts.
/// Security Findings are otherwise always tenant-scoped
/// (`workspace_id`/`namespace_id`), but backlog depth/age is a GLOBAL,
/// process-wide operational signal -- it says nothing about any one tenant.
/// Rather than inventing a parallel non-scoped alert channel (event-ingest
/// has no metrics/Prometheus endpoint by design), this reuses the existing
/// scoped Security Alerts path with a fixed, reserved "scope" that is not,
/// and can never be, a real tenant: both constants pass `is_scope_identifier`
/// (so `validate_scope` accepts them unchanged) but neither can collide with
/// an operator-issued tenant scope, because `APEX_ALLOWED_SCOPES` is the only
/// way a caller's bearer token is ever bound to a scope, and an operator
/// would have to deliberately allow-list `apex-operations/ingest-backlog` as
/// a tenant for that collision to happen. Findings recorded here are read
/// through the same `security_findings_for_scope` API as any tenant's,
/// scoped to whichever caller is authorized for this reserved scope (an
/// operator/on-call identity, not a tenant).
pub(crate) const OPERATIONAL_WORKSPACE_ID: &str = "apex-operations";
pub(crate) const OPERATIONAL_NAMESPACE_ID: &str = "ingest-backlog";

pub struct IngestGateway<P: EventPublisher> {
    publisher: P,
    idempotency: Box<dyn IdempotencyStore + Send>,
    security_store: Option<SharedSecurityStore>,
}

enum SecurityAlertBackend {
    Memory(FindingStore),
    Journal(FindingJournal),
}

/// A cloneable handle to a Security Alert backend (in-memory or journal).
///
/// Phase 0.6 item 2b replaces the single admission `Mutex<adapter>` with a
/// POOL of N `AuthenticatedIngestAdapter`s (see
/// `auth::service::AuthenticatedGrpcService`), each wrapping its own
/// `IngestGateway<P>`. If each pool member kept its own independent
/// `FindingStore`, findings would scatter across pool members -- a caller
/// reading `security_findings_for_scope` through whichever pool member
/// happens to answer its request would see only a fraction of what was
/// actually recorded, depending on which slot handled which prior request.
/// `SharedSecurityStore` lets every pool member (and
/// `AuthenticatedGrpcService` itself, for signal recording that must not
/// wait on a busy admission adapter) record into and read from exactly one
/// combined backend, via `IngestGateway::shared_security_store` /
/// `with_shared_security_store`.
///
/// Interior mutability (`Mutex`) rather than requiring `&mut self` on every
/// gateway that holds a clone is what makes sharing possible: the store is a
/// side channel from the admission decision (a failed or skipped write here
/// never changes it), so a brief, uncontended lock here is a very different
/// hazard than the admission mutex this whole change removes.
#[derive(Clone)]
pub struct SharedSecurityStore(Arc<Mutex<SecurityAlertBackend>>);

impl SharedSecurityStore {
    fn new(backend: SecurityAlertBackend) -> Self {
        Self(Arc::new(Mutex::new(backend)))
    }

    /// Recovers a poisoned lock rather than propagating the poison. The
    /// backend's own operations (`FindingStore::append`,
    /// `FindingJournal::record_detection`) do not hold multi-step invariants
    /// across an await/panic boundary here, and every caller of a
    /// `SharedSecurityStore` method already treats a failed write as a
    /// silent no-op (see `record_signal_parts`'s doc comment) -- so refusing
    /// every future finding for the rest of the process over one unrelated
    /// panic would be a strictly worse outcome than continuing with
    /// whatever the backend held at the moment of the panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, SecurityAlertBackend> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// True only for the in-memory backend. Mirrors the pre-pool
    /// `IngestGateway::security_store()` accessor, which likewise reported
    /// absence for a journal-backed store -- callers that need this
    /// distinction (tests only; no production caller) never needed access
    /// to the store's contents, just which backend is configured.
    fn is_memory_backed(&self) -> bool {
        matches!(&*self.guard(), SecurityAlertBackend::Memory(_))
    }

    /// Returns findings for exactly one caller-selected scope. No API here
    /// exposes the backing store's global finding collection.
    pub fn findings_for_scope(
        &self,
        caller: &Caller,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Vec<SecurityFinding>, FindingError> {
        match &*self.guard() {
            SecurityAlertBackend::Memory(store) => Ok(store
                .findings_for_scope(caller, workspace_id, namespace_id)?
                .into_iter()
                .cloned()
                .collect()),
            SecurityAlertBackend::Journal(journal) => Ok(journal
                .store()
                .findings_for_scope(caller, workspace_id, namespace_id)?
                .into_iter()
                .cloned()
                .collect()),
        }
    }

    /// Records a redacted, best-effort finding. Alert persistence is
    /// secondary to whatever decision the caller already made: a failed or
    /// skipped write here never changes that decision, so every failure
    /// mode (detector rejection, poisoned lock) is silently swallowed,
    /// exactly like the pre-pool `IngestGateway::record_security_signal_parts`.
    fn record_signal_parts(
        &self,
        signal: SecuritySignal,
        workspace_id: &str,
        namespace_id: &str,
        event_id: &str,
        field_path: &str,
        envelope: &[u8],
    ) {
        let value_hash = format!("{:x}", Sha256::digest(envelope));
        let input = DetectionInput {
            signal,
            workspace_id: workspace_id.to_owned(),
            namespace_id: namespace_id.to_owned(),
            event_id: event_id.to_owned(),
            field_path: field_path.to_owned(),
            value_hash,
        };
        match &mut *self.guard() {
            SecurityAlertBackend::Memory(store) => {
                let _ = detect_and_record(store, input);
            }
            SecurityAlertBackend::Journal(journal) => {
                let _ = journal.record_detection(input);
            }
        }
    }

    /// See `IngestGateway::record_rejected_envelope_signal`.
    pub(crate) fn record_rejected_envelope_signal(
        &self,
        signal: SecuritySignal,
        envelope: &proto::EventEnvelope,
    ) {
        let Some(scope) = envelope.scope.as_ref() else {
            return;
        };
        if !is_lowercase_uuidv7(&envelope.event_id)
            || !is_scope_identifier(&scope.workspace_id)
            || !is_scope_identifier(&scope.namespace_id)
        {
            return;
        }
        let bytes = envelope.encode_to_vec();
        self.record_signal_parts(
            signal,
            &scope.workspace_id,
            &scope.namespace_id,
            &envelope.event_id,
            "event.envelope",
            &bytes,
        );
    }

    /// See `IngestGateway::record_backlog_alert`.
    pub(crate) fn record_backlog_alert(
        &self,
        depth: u64,
        oldest_pending_millis: Option<u64>,
        alert_depth: u64,
        alert_age_millis: u64,
    ) {
        let Ok(event_id) = synthetic_operational_event_id() else {
            return;
        };
        let detail = format!(
            "depth={depth} oldest_pending_ms={} alert_depth={alert_depth} alert_age_ms={alert_age_millis}",
            oldest_pending_millis
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned())
        );
        self.record_signal_parts(
            SecuritySignal::BacklogDegraded,
            OPERATIONAL_WORKSPACE_ID,
            OPERATIONAL_NAMESPACE_ID,
            &event_id,
            "outbox.backlog",
            detail.as_bytes(),
        );
    }
}

impl<P: EventPublisher> IngestGateway<P> {
    pub fn new(publisher: P) -> Self {
        Self::with_idempotency_capacity(publisher, crate::DEFAULT_IDEMPOTENCY_CAPACITY)
    }

    pub fn with_idempotency_capacity(publisher: P, idempotency_capacity: usize) -> Self {
        let idempotency = InMemoryIdempotencyStore::new(idempotency_capacity)
            .expect("validated staging idempotency capacity");
        Self {
            publisher,
            idempotency: Box::new(idempotency),
            security_store: None,
        }
    }

    pub fn with_idempotency_store(
        publisher: P,
        idempotency: Box<dyn IdempotencyStore + Send>,
    ) -> Self {
        Self {
            publisher,
            idempotency,
            security_store: None,
        }
    }

    /// Enables bounded, redacted Security Alerts for admission denials.
    /// Alert persistence is secondary to the admission decision: a failed
    /// alert write never turns a denied request into an accepted request.
    pub fn with_security_store(mut self, capacity: usize) -> Result<Self, GatewayError> {
        self.security_store = Some(SharedSecurityStore::new(SecurityAlertBackend::Memory(
            FindingStore::new(capacity)
                .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?,
        )));
        Ok(self)
    }

    pub fn with_security_journal(mut self, journal: FindingJournal) -> Self {
        self.security_store = Some(SharedSecurityStore::new(SecurityAlertBackend::Journal(
            journal,
        )));
        self
    }

    /// Attaches an existing shared Security Alert backend instead of
    /// creating a new, independent one -- see `SharedSecurityStore`'s doc
    /// comment. Used by `startup::service::run` to give every
    /// `IngestGateway` in the Phase 0.6 item 2b admission pool the same
    /// combined finding store.
    pub fn with_shared_security_store(mut self, shared: SharedSecurityStore) -> Self {
        self.security_store = Some(shared);
        self
    }

    /// Returns a cloneable handle to this gateway's Security Alert backend,
    /// if one is configured -- for attaching to other pool members via
    /// `with_shared_security_store`, or for `AuthenticatedGrpcService` to
    /// record signals directly without waiting on any pool member's
    /// per-adapter lock.
    pub fn shared_security_store(&self) -> Option<SharedSecurityStore> {
        self.security_store.clone()
    }

    /// True only when a Security Alert backend is configured AND it is the
    /// in-memory backend. Mirrors the pre-pool `security_store().is_some()`
    /// accessor exactly: it never exposed the journal-backed case either.
    pub fn has_memory_security_store(&self) -> bool {
        self.security_store
            .as_ref()
            .is_some_and(SharedSecurityStore::is_memory_backed)
    }

    /// Returns findings for exactly one caller-selected scope. No gateway API
    /// exposes the backing store's global finding collection.
    pub fn security_findings_for_scope(
        &self,
        caller: &Caller,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Option<Vec<SecurityFinding>>, FindingError> {
        let Some(store) = self.security_store.as_ref() else {
            return Ok(None);
        };
        Ok(Some(store.findings_for_scope(
            caller,
            workspace_id,
            namespace_id,
        )?))
    }

    pub fn publisher(&self) -> &P {
        &self.publisher
    }

    pub fn replay_pending(&mut self) -> Result<(), GatewayError>
    where
        P: PendingEventReplayer,
    {
        // Callers through this API (the admission-side one-shot pre-serve
        // catch-up in `startup::service::run`, and the manual/fallback
        // `spawn_replay_worker` path in `auth/service.rs`) only ever cared
        // whether the cycle succeeded, never whether it settled anything --
        // that distinction is Phase 0.6 item 4's continuous-drain signal,
        // consumed directly by `spawn_fanout_worker` instead. Preserve this
        // method's original `()` contract rather than threading the new bool
        // through every caller.
        self.publisher.replay_pending().map(|_| ())
    }

    /// Prunes completed outbox rows outside `retention_millis` and compacts
    /// the durable journal where applicable. See
    /// `EventOutbox::maintain` -- this only forwards to it.
    pub fn maintain_outbox(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
    ) -> Result<(), GatewayError>
    where
        P: OutboxMaintainer,
    {
        self.publisher.maintain_outbox(now_millis, retention_millis)
    }

    /// Prunes committed idempotency keys outside `retention_millis`.
    /// Durable stores override `IdempotencyStore::maintain`; memory-backed
    /// stores intentionally retain their process-lifetime state.
    pub fn maintain_idempotency(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
    ) -> Result<(), GatewayError> {
        self.idempotency.maintain(now_millis, retention_millis)
    }

    pub fn ingest(
        &mut self,
        caller: &Caller,
        event: IngestRequest,
    ) -> Result<IngestOutcome, GatewayError> {
        let result = self.ingest_inner(caller, &event);
        if let Err(error) = &result
            && let Some(signal) = signal_for_error(error.code)
        {
            self.record_security_signal(signal, &event);
        }
        result
    }

    fn ingest_inner(
        &mut self,
        caller: &Caller,
        event: &IngestRequest,
    ) -> Result<IngestOutcome, GatewayError> {
        if !caller.is_valid() || caller.bound_agent_id().is_none() {
            return Err(GatewayError::new(GatewayErrorCode::Unauthenticated));
        }
        if !is_scope_identifier(&event.workspace_id) || !is_scope_identifier(&event.namespace_id) {
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        let scope_key = event.scope_key().to_owned();
        if !caller.allows_scope(&scope_key) {
            self.record_security_signal(SecuritySignal::ScopeIdentityDenied, event);
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        // Preserve deterministic request-validation errors before decoding the
        // protobuf needed for workload binding. This keeps malformed IDs,
        // empty envelopes, and oversized payloads diagnosable without letting
        // an attacker use an invalid payload to probe identity details.
        if !is_lowercase_uuidv7(&event.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if event.envelope.is_empty() {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
        }
        if event.envelope.len() > crate::MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        let bound_agent_id = caller
            .bound_agent_id()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::Unauthenticated))?;
        let envelope = proto::EventEnvelope::decode(event.envelope.as_slice())
            .map_err(|_| GatewayError::new(GatewayErrorCode::InvalidEnvelope))?;
        // The runtime workload identity is an agent identity, not a delegated
        // user/system identity. Requiring an AGENT actor with the same ID
        // prevents a shared credential from minting arbitrary actor identities.
        let agent_actor_matches = envelope
            .actor
            .as_ref()
            .is_some_and(|actor| actor.r#type == 2 && actor.id == bound_agent_id);
        if envelope.agent_id != bound_agent_id || !agent_actor_matches {
            self.record_security_signal(SecuritySignal::ScopeIdentityDenied, event);
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        let payload_fingerprint: [u8; 32] = Sha256::digest(&event.envelope).into();
        let reservation = match self.idempotency.reserve(
            IdempotencyKey {
                workspace_id: event.workspace_id.clone(),
                namespace_id: event.namespace_id.clone(),
                event_id: event.event_id.clone(),
            },
            payload_fingerprint,
        )? {
            ReservationResult::Duplicate => return Ok(IngestOutcome::Duplicate),
            ReservationResult::InProgress => {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyInProgress));
            }
            ReservationResult::Conflict => {
                self.record_security_signal(SecuritySignal::TelemetryIntegrity, event);
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyConflict));
            }
            ReservationResult::Reserved(reservation) => reservation,
        };
        let publish_result = catch_unwind(AssertUnwindSafe(|| self.publisher.publish(event)))
            .map_err(|_| GatewayError::internal())?;
        let outcome = match publish_result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.idempotency.abort(reservation);
                return Err(error);
            }
        };
        // Only the durable outbox can prove that a retry will not fan out a
        // second time. Plain publishers retain an uncertain reservation after
        // a commit failure; releasing it there would make side effects
        // duplicable without a reconciliation authority.
        if let Err(error) = self.idempotency.commit(reservation) {
            if self.publisher.can_reconcile_commit_failure() {
                self.idempotency.abort(reservation);
            }
            return Err(error);
        }
        Ok(match outcome {
            PublishOutcome::Published => IngestOutcome::Accepted,
            // The outbox already had this exact event completed while the
            // idempotency journal did not -- the signature of a torn fanout
            // that aborted the reservation and was later reconciled by the
            // replay worker, which completes outbox rows without settling
            // idempotency state.
            //
            // Two things happen here. The commit above heals the divergence,
            // so the *next* submission takes the fast Duplicate path in
            // `reserve()` and never reaches the publisher at all. And the
            // answer stops lying: reporting `Accepted` told a producer its
            // event had just been stored, when it had in fact been stored
            // earlier by the replay worker. A producer that treats the
            // acknowledgement as "this call made it durable" -- the exact
            // reading the outbox exists to support -- was being misled.
            PublishOutcome::AlreadyComplete => IngestOutcome::Duplicate,
        })
    }

    fn record_security_signal(&self, signal: SecuritySignal, event: &IngestRequest) {
        if let Some(store) = &self.security_store {
            store.record_signal_parts(
                signal,
                &event.workspace_id,
                &event.namespace_id,
                &event.event_id,
                "event.envelope",
                &event.envelope,
            );
        }
    }

    /// Reports current backlog depth and oldest-pending age. Forwards to the
    /// durable outbox behind `self.publisher` -- see `BacklogObserver`. Only
    /// available when `P` actually wraps one (`OutboxedPublisher`), exactly
    /// like `maintain_outbox`/`replay_pending` above.
    pub fn backlog_stats(&mut self) -> Result<(u64, Option<u64>), GatewayError>
    where
        P: BacklogObserver,
    {
        self.publisher.backlog_stats()
    }

    /// Records a safe, redacted finding for a validation denial that occurs
    /// before an `IngestRequest` exists. Only fields already validated by the
    /// envelope boundary are accepted into the finding evidence.
    pub(crate) fn record_rejected_envelope_signal(
        &self,
        signal: SecuritySignal,
        envelope: &proto::EventEnvelope,
    ) {
        if let Some(store) = &self.security_store {
            store.record_rejected_envelope_signal(signal, envelope);
        }
    }
}

/// Synthesizes a UUIDv7-shaped identifier for a backlog alert's evidence.
/// `EvidenceRef::new` (via `is_lowercase_uuidv7`) requires one, but a backlog
/// alert has no real `event_id` -- it is not about any single event. This is
/// a process-local, per-call random id, not derived from any tenant data;
/// its only job is to satisfy the evidence shape and give repeated alerts
/// distinct identities. Mirrors `security::ids::uuid7`'s format (that
/// function is `pub(crate)` inside the private `security::ids` module, so it
/// is not reachable from here) rather than adding a new crate-wide export for
/// a single caller.
fn synthetic_operational_event_id() -> Result<String, GatewayError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| GatewayError::internal())?;
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    let timestamp = now_millis & 0x0000_ffff_ffff_ffff;
    bytes[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn signal_for_error(code: GatewayErrorCode) -> Option<SecuritySignal> {
    match code {
        GatewayErrorCode::IdempotencyCapacity | GatewayErrorCode::PayloadTooLarge => {
            Some(SecuritySignal::AdmissionAbuse)
        }
        GatewayErrorCode::IdempotencyConflict => Some(SecuritySignal::TelemetryIntegrity),
        GatewayErrorCode::ScopeDenied => Some(SecuritySignal::ScopeIdentityDenied),
        _ => None,
    }
}
