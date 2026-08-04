use super::IngestOutcome;
use super::core::IngestGateway;
use super::publisher::EventPublisher;
use crate::outbox::PendingEventReplayer;
use crate::{GatewayError, GatewayErrorCode, SecuritySignal, proto, validation::Caller};

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

    pub(crate) fn replay_pending(&mut self) -> Result<(), GatewayError>
    where
        P: PendingEventReplayer,
    {
        self.gateway.replay_pending()
    }

    pub(crate) fn record_security_signal(
        &mut self,
        signal: SecuritySignal,
        envelope: &proto::EventEnvelope,
    ) {
        self.gateway
            .record_rejected_envelope_signal(signal, envelope);
    }

    pub fn ingest_envelope(
        &mut self,
        caller: &Caller,
        envelope: proto::EventEnvelope,
    ) -> Result<proto::IngestResponse, GatewayError> {
        let validation_copy = envelope.clone();
        let request = match crate::IngestRequest::from_validated_transport(envelope) {
            Ok(request) => request,
            Err(error) => {
                if let Some(signal) = validation_signal_for_error(error.code) {
                    self.gateway
                        .record_rejected_envelope_signal(signal, &validation_copy);
                }
                return Err(error);
            }
        };
        let duplicate = match self.gateway.ingest(caller, request) {
            Ok(outcome) => matches!(outcome, IngestOutcome::Duplicate),
            Err(error) => return Err(error),
        };
        Ok(proto::IngestResponse { duplicate })
    }
}

fn validation_signal_for_error(code: GatewayErrorCode) -> Option<SecuritySignal> {
    match code {
        GatewayErrorCode::SecretExposure => Some(SecuritySignal::SecretExposure),
        GatewayErrorCode::PayloadTooLarge
        | GatewayErrorCode::InvalidEnvelope
        | GatewayErrorCode::InvalidStructure => Some(SecuritySignal::AdmissionAbuse),
        _ => None,
    }
}
