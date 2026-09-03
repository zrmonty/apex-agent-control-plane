use crate::{GatewayError, IngestRequest};

/// Durable sink contract for downstream projections. Implementations must use
/// `event_id` as their idempotency key and must not log or reinterpret payload
/// bytes supplied by the validated ingest boundary.
pub trait DurableEventSink {
    fn write_event(&mut self, event: &IngestRequest) -> Result<(), GatewayError>;
}

/// ClickHouse projection seam. The concrete HTTP/native client belongs behind
/// this trait so transport errors remain redaction-safe `GatewayError` values.
pub trait ClickHousePublisher: DurableEventSink {}

/// Object-lock/archive projection seam. Implementations must commit the event
/// manifest and canonical bytes under the event ID before acknowledging success.
pub trait ArchivePublisher: DurableEventSink {}
