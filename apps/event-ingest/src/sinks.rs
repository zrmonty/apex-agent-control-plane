use crate::{EventPublisher, GatewayError, IngestRequest, JetStreamPublisher, JetStreamTransport};
use std::panic::{AssertUnwindSafe, catch_unwind};

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

/// Bounded retry wrapper for downstream projections. Concrete sinks must use
/// the event ID as their durable idempotency key so a retry cannot create a
/// second logical record after an acknowledgement or connection ambiguity.
pub struct RetryingDurableSink<S: DurableEventSink> {
    sink: S,
    max_attempts: usize,
}

impl<S: DurableEventSink> RetryingDurableSink<S> {
    pub fn new(sink: S, max_attempts: usize) -> Result<Self, GatewayError> {
        if max_attempts == 0 || max_attempts > 8 {
            return Err(GatewayError::invalid_retry_configuration());
        }
        Ok(Self { sink, max_attempts })
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }
}

impl<S: DurableEventSink> DurableEventSink for RetryingDurableSink<S> {
    fn write_event(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        let mut last_error = None;
        for _ in 0..self.max_attempts {
            match self.sink.write_event(event) {
                Ok(()) => return Ok(()),
                Err(error) if error.retryable => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(GatewayError::publish_failed))
    }
}

impl<S: DurableEventSink> ClickHousePublisher for RetryingDurableSink<S> {}
impl<S: DurableEventSink> ArchivePublisher for RetryingDurableSink<S> {}

pub struct DurableFanoutPublisher<J: JetStreamTransport, C, A> {
    jetstream: JetStreamPublisher<J>,
    clickhouse: C,
    archive: A,
}

impl<J, C, A> DurableFanoutPublisher<J, C, A>
where
    J: JetStreamTransport,
    C: ClickHousePublisher,
    A: ArchivePublisher,
{
    pub fn new(jetstream: J, clickhouse: C, archive: A) -> Self {
        Self {
            jetstream: JetStreamPublisher::new(jetstream),
            clickhouse,
            archive,
        }
    }

    pub fn jetstream(&self) -> &JetStreamPublisher<J> {
        &self.jetstream
    }

    pub fn clickhouse(&self) -> &C {
        &self.clickhouse
    }

    pub fn archive(&self) -> &A {
        &self.archive
    }
}

impl<J, C, A> EventPublisher for DurableFanoutPublisher<J, C, A>
where
    J: JetStreamTransport,
    C: ClickHousePublisher,
    A: ArchivePublisher,
{
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        catch_unwind(AssertUnwindSafe(|| self.jetstream.publish(event)))
            .map_err(|_| GatewayError::internal())??;
        let clickhouse = catch_unwind(AssertUnwindSafe(|| self.clickhouse.write_event(event)))
            .map_err(|_| GatewayError::internal())?;
        clickhouse?;
        catch_unwind(AssertUnwindSafe(|| self.archive.write_event(event)))
            .map_err(|_| GatewayError::internal())?
    }
}
