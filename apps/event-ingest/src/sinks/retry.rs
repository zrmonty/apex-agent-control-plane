use super::traits::{ArchivePublisher, ClickHousePublisher, DurableEventSink};
use crate::{GatewayError, IngestRequest};

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
