use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::{
    GatewayError, GatewayErrorCode, proto,
    security::{DetectionInput, FindingStore, SecuritySignal, detect_and_record},
    validation::{Caller, IngestRequest, is_lowercase_uuidv7, is_scope_identifier},
};

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
    accepted_event_ids: HashMap<(String, String), [u8; 32]>,
    idempotency_capacity: usize,
    security_store: Option<FindingStore>,
}

impl<P: EventPublisher> IngestGateway<P> {
    pub fn new(publisher: P) -> Self {
        Self::with_idempotency_capacity(publisher, crate::DEFAULT_IDEMPOTENCY_CAPACITY)
    }

    pub fn with_idempotency_capacity(publisher: P, idempotency_capacity: usize) -> Self {
        Self {
            publisher,
            accepted_event_ids: HashMap::new(),
            idempotency_capacity,
            security_store: None,
        }
    }

    /// Enables bounded, redacted Security Alerts for admission denials.
    /// Alert persistence is secondary to the admission decision: a failed
    /// alert write never turns a denied request into an accepted request.
    pub fn with_security_store(mut self, capacity: usize) -> Result<Self, GatewayError> {
        self.security_store = Some(
            FindingStore::new(capacity)
                .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?,
        );
        Ok(self)
    }

    pub fn security_store(&self) -> Option<&FindingStore> {
        self.security_store.as_ref()
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
        if !is_lowercase_uuidv7(&event.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if event.envelope.is_empty() {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
        }
        if event.envelope.len() > crate::MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        let idempotency_key = (scope_key, event.event_id.clone());
        let payload_fingerprint: [u8; 32] = Sha256::digest(&event.envelope).into();
        if let Some(original_fingerprint) = self.accepted_event_ids.get(&idempotency_key) {
            if original_fingerprint == &payload_fingerprint {
                return Ok(IngestOutcome::Duplicate);
            }
            self.record_security_signal(SecuritySignal::TelemetryIntegrity, &event);
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyConflict));
        }
        if self.accepted_event_ids.len() >= self.idempotency_capacity {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        self.publisher.publish(&event)?;
        self.accepted_event_ids
            .insert(idempotency_key, payload_fingerprint);
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
        let _ = detect_and_record(
            store,
            DetectionInput {
                signal,
                workspace_id: event.workspace_id.clone(),
                namespace_id: event.namespace_id.clone(),
                event_id: event.event_id.clone(),
                field_path: "event.envelope".to_owned(),
                value_hash,
            },
        );
    }
}
