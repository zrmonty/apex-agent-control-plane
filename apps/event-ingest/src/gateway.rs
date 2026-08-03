use crate::{
    GatewayError, GatewayErrorCode,
    idempotency::{IdempotencyKey, IdempotencyStore, InMemoryIdempotencyStore, ReservationResult},
    persistence::FindingJournal,
    proto,
    security::{DetectionInput, FindingStore, SecurityFinding, SecuritySignal, detect_and_record},
    validation::{Caller, IngestRequest, is_lowercase_uuidv7, is_scope_identifier},
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Accepted,
    Duplicate,
}

pub struct AuthenticatedIngestAdapter<P: EventPublisher> {
    gateway: IngestGateway<P>,
}

impl<P: EventPublisher> AuthenticatedIngestAdapter<P> {
    pub fn new(gateway: IngestGateway<P>) -> Self {
        Self { gateway }
    }

    pub fn gateway(&self) -> &IngestGateway<P> {
        &self.gateway
    }

    pub fn ingest_envelope(
        &mut self,
        caller: &Caller,
        envelope: proto::EventEnvelope,
    ) -> Result<proto::IngestResponse, GatewayError> {
        let request = IngestRequest::from_validated_transport(envelope)?;
        let duplicate = matches!(
            self.gateway.ingest(caller, request)?,
            IngestOutcome::Duplicate
        );
        Ok(proto::IngestResponse { duplicate })
    }
}

pub trait EventPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError>;
}

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

    /// Returns findings regardless of whether the configured backend is the
    /// in-memory staging store or the restart-safe journal.
    pub fn security_findings(&self) -> Option<Vec<&SecurityFinding>> {
        match self.security_store.as_ref()? {
            SecurityAlertBackend::Memory(store) => Some(store.findings().iter().collect()),
            SecurityAlertBackend::Journal(journal) => {
                Some(journal.store().findings().iter().collect())
            }
        }
    }

    pub fn with_security_journal(mut self, journal: FindingJournal) -> Self {
        self.security_store = Some(SecurityAlertBackend::Journal(journal));
        self
    }

    pub fn publisher(&self) -> &P {
        &self.publisher
    }

    pub fn ingest(
        &mut self,
        caller: &Caller,
        event: IngestRequest,
    ) -> Result<IngestOutcome, GatewayError> {
        if !caller.authenticated {
            return Err(GatewayError::new(GatewayErrorCode::Unauthenticated));
        }
        if !is_scope_identifier(&event.workspace_id) || !is_scope_identifier(&event.namespace_id) {
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        let scope_key = event.scope_key().to_owned();
        if !caller.allowed_scopes.contains(&scope_key) {
            self.record_security_signal(SecuritySignal::ScopeIdentityDenied, &event);
            return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
        }
        if let Some(bound_agent_id) = caller.bound_agent_id() {
            let envelope = proto::EventEnvelope::decode(event.envelope.as_slice())
                .map_err(|_| GatewayError::new(GatewayErrorCode::InvalidEnvelope))?;
            let agent_actor_matches = envelope
                .actor
                .as_ref()
                .filter(|actor| actor.r#type == 2)
                .is_none_or(|actor| actor.id == bound_agent_id);
            if envelope.agent_id != bound_agent_id || !agent_actor_matches {
                self.record_security_signal(SecuritySignal::ScopeIdentityDenied, &event);
                return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
            }
        }
        if !is_lowercase_uuidv7(&event.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if event.envelope.is_empty() {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
        }
        if event.envelope.len() > crate::MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
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
        // The publisher has already produced side effects. Never release the
        // reservation after a commit failure: doing so would allow a retry to
        // replay an event whose durable outcome is uncertain.
        self.idempotency.commit(reservation)?;
        Ok(IngestOutcome::Accepted)
    }

    fn record_security_signal(&mut self, signal: SecuritySignal, event: &IngestRequest) {
        let Some(store) = self.security_store.as_mut() else {
            return;
        };
        let value_hash = format!("{:x}", Sha256::digest(&event.envelope));
        // The event has already passed the scope and UUID checks at each call
        // site. Detector failures are deliberately ignored so alerting cannot
        // change the fail-closed admission result or expose persistence detail.
        let input = DetectionInput {
            signal,
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
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
