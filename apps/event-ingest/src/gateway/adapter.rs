use super::IngestOutcome;
use super::core::IngestGateway;
use super::publisher::EventPublisher;
use crate::outbox::{BacklogObserver, OutboxMaintainer, PendingEventReplayer};
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

    pub(crate) fn maintain_outbox(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
    ) -> Result<(), GatewayError>
    where
        P: OutboxMaintainer,
    {
        self.gateway.maintain_outbox(now_millis, retention_millis)
    }

    /// See `IngestGateway::backlog_stats`. Used only by
    /// `AuthenticatedGrpcService::spawn_backlog_monitor` (Phase 0.6 item 6).
    pub(crate) fn backlog_stats(&mut self) -> Result<(u64, Option<u64>), GatewayError>
    where
        P: BacklogObserver,
    {
        self.gateway.backlog_stats()
    }

    pub fn ingest_envelope(
        &mut self,
        caller: &Caller,
        envelope: proto::EventEnvelope,
    ) -> Result<proto::IngestResponse, GatewayError> {
        let request = match crate::IngestRequest::from_validated_transport_ref(&envelope) {
            Ok(request) => request,
            Err(error) => {
                if let Some(signal) = validation_signal_for_error(error.code) {
                    self.gateway
                        .record_rejected_envelope_signal(signal, &envelope);
                }
                return Err(error);
            }
        };
        let outcome = self.gateway.ingest(caller, request)?;
        let duplicate = matches!(outcome, IngestOutcome::Duplicate);
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
