use crate::GatewayError;

pub trait JetStreamTransport {
    /// Publishes one admitted envelope while preserving the broker deduplication key.
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError>;
}

/// Bounded retry wrapper for transient broker failures. The transport must use
/// the event ID as its broker deduplication key so retrying is idempotent.
pub struct RetryingJetStreamTransport<T: JetStreamTransport> {
    transport: T,
    max_attempts: usize,
}

impl<T: JetStreamTransport> RetryingJetStreamTransport<T> {
    pub fn new(transport: T, max_attempts: usize) -> Result<Self, GatewayError> {
        if max_attempts == 0 || max_attempts > 8 {
            return Err(GatewayError::invalid_retry_configuration());
        }
        Ok(Self {
            transport,
            max_attempts,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: JetStreamTransport> JetStreamTransport for RetryingJetStreamTransport<T> {
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        let mut last_error = None;
        for _ in 0..self.max_attempts {
            match self.transport.publish_event(subject, message_id, payload) {
                Ok(()) => return Ok(()),
                Err(error) if error.retryable => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(GatewayError::publish_failed))
    }
}
