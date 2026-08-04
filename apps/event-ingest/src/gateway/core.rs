use std::panic::{AssertUnwindSafe, catch_unwind};

use prost::Message;
use sha2::{Digest, Sha256};

use super::IngestOutcome;
use super::publisher::EventPublisher;
use crate::outbox::PendingEventReplayer;
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

pub struct IngestGateway<P: EventPublisher> {
    publisher: P,
    idempotency: Box<dyn IdempotencyStore + Send>,
    security_store: Option<SecurityAlertBackend>,
}

enum SecurityAlertBackend {
    Memory(FindingStore),
    Journal(FindingJournal),
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
        self.security_store = Some(SecurityAlertBackend::Memory(
            FindingStore::new(capacity)
                .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?,
        ));
        Ok(self)
    }

    pub fn security_store(&self) -> Option<&FindingStore> {
        match self.security_store.as_ref() {
            Some(SecurityAlertBackend::Memory(store)) => Some(store),
            _ => None,
        }
    }

    /// Returns findings for exactly one caller-selected scope. No gateway API
    /// exposes the backing store's global finding collection.
    pub fn security_findings_for_scope(
        &self,
        caller: &Caller,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Option<Vec<&SecurityFinding>>, FindingError> {
        let Some(store) = self.security_store.as_ref() else {
            return Ok(None);
        };
        match store {
            SecurityAlertBackend::Memory(store) => Ok(Some(store.findings_for_scope(
                caller,
                workspace_id,
                namespace_id,
            )?)),
            SecurityAlertBackend::Journal(journal) => Ok(Some(
                journal
                    .store()
                    .findings_for_scope(caller, workspace_id, namespace_id)?,
            )),
        }
    }

    pub fn with_security_journal(mut self, journal: FindingJournal) -> Self {
        self.security_store = Some(SecurityAlertBackend::Journal(journal));
        self
    }

    pub fn publisher(&self) -> &P {
        &self.publisher
    }

    pub fn replay_pending(&mut self) -> Result<(), GatewayError>
    where
        P: PendingEventReplayer,
    {
        self.publisher.replay_pending()
    }

    pub fn ingest(
        &mut self,
        caller: &Caller,
        event: IngestRequest,
    ) -> Result<IngestOutcome, GatewayError> {
        let signal_event = event.clone();
        let result = self.ingest_inner(caller, event);
        if let Err(error) = &result
            && let Some(signal) = signal_for_error(error.code)
        {
            self.record_security_signal(signal, &signal_event);
        }
        result
    }

    fn ingest_inner(
        &mut self,
        caller: &Caller,
        event: IngestRequest,
    ) -> Result<IngestOutcome, GatewayError> {
        if !caller.is_valid() || caller.bound_agent_id().is_none() {
            return Err(GatewayError::new(GatewayErrorCode::Unauthenticated));
        }
        if !is_scope_identifier(&event.workspace_id) || !is_scope_identifier(&event.namespace_id) {
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        let scope_key = event.scope_key().to_owned();
        if !caller.allows_scope(&scope_key) {
            self.record_security_signal(SecuritySignal::ScopeIdentityDenied, &event);
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
            self.record_security_signal(SecuritySignal::ScopeIdentityDenied, &event);
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
                self.record_security_signal(SecuritySignal::TelemetryIntegrity, &event);
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyConflict));
            }
            ReservationResult::Reserved(reservation) => reservation,
        };
        let publish_result = catch_unwind(AssertUnwindSafe(|| self.publisher.publish(&event)))
            .map_err(|_| GatewayError::internal())?;
        if let Err(error) = publish_result {
            self.idempotency.abort(reservation);
            return Err(error);
        }
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
        Ok(IngestOutcome::Accepted)
    }

    fn record_security_signal(&mut self, signal: SecuritySignal, event: &IngestRequest) {
        self.record_security_signal_parts(
            signal,
            &event.workspace_id,
            &event.namespace_id,
            &event.event_id,
            &event.envelope,
        );
    }

    /// Records a safe, redacted finding for a validation denial that occurs
    /// before an `IngestRequest` exists. Only fields already validated by the
    /// envelope boundary are accepted into the finding evidence.
    pub(crate) fn record_rejected_envelope_signal(
        &mut self,
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
        self.record_security_signal_parts(
            signal,
            &scope.workspace_id,
            &scope.namespace_id,
            &envelope.event_id,
            &bytes,
        );
    }

    fn record_security_signal_parts(
        &mut self,
        signal: SecuritySignal,
        workspace_id: &str,
        namespace_id: &str,
        event_id: &str,
        envelope: &[u8],
    ) {
        let Some(store) = self.security_store.as_mut() else {
            return;
        };
        let value_hash = format!("{:x}", Sha256::digest(envelope));
        // The event has already passed the scope and UUID checks at each call
        // site. Detector failures are deliberately ignored so alerting cannot
        // change the fail-closed admission result or expose persistence detail.
        let input = DetectionInput {
            signal,
            workspace_id: workspace_id.to_owned(),
            namespace_id: namespace_id.to_owned(),
            event_id: event_id.to_owned(),
            field_path: "event.envelope".to_owned(),
            value_hash,
        };
        match store {
            SecurityAlertBackend::Memory(store) => {
                let _ = detect_and_record(store, input);
            }
            SecurityAlertBackend::Journal(journal) => {
                let _ = journal.record_detection(input);
            }
        }
    }
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
