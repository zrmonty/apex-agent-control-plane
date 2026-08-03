use crate::{
    EventPublisher, GatewayError, GatewayErrorCode, IngestRequest, MAX_ENVELOPE_BYTES,
    MAX_JETSTREAM_SUBJECT_BYTES, is_lowercase_uuidv7, is_scope_identifier,
};

pub trait JetStreamTransport {
    /// Publishes one admitted envelope while preserving the broker deduplication key.
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError>;
}

pub struct JetStreamPublisher<T: JetStreamTransport> {
    transport: T,
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

impl<T: JetStreamTransport> JetStreamPublisher<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: JetStreamTransport> EventPublisher for JetStreamPublisher<T> {
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        if !is_scope_identifier(&event.workspace_id) || !is_scope_identifier(&event.namespace_id) {
            return Err(GatewayError::scope_denied());
        }
        if !is_lowercase_uuidv7(&event.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if event.envelope.is_empty() {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
        }
        if event.envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        let subject = format!(
            "apex.events.{}.{}",
            encode_subject_component(&event.workspace_id),
            encode_subject_component(&event.namespace_id)
        );
        if subject.len() > MAX_JETSTREAM_SUBJECT_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::SubjectTooLong));
        }
        self.transport
            .publish_event(&subject, &event.event_id, &event.envelope)
    }
}

fn encode_subject_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2 + 1);
    encoded.push('x');
    for byte in value.bytes() {
        encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        encoded.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    encoded
}

#[derive(Debug, Default)]
pub struct InMemoryPublisher {
    published_event_ids: Vec<String>,
}

impl InMemoryPublisher {
    pub fn published_event_ids(&self) -> &[String] {
        &self.published_event_ids
    }
}

impl EventPublisher for InMemoryPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        self.published_event_ids.push(event.event_id.clone());
        Ok(())
    }
}
