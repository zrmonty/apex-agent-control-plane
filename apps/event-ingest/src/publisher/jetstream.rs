use super::transport::JetStreamTransport;
use crate::{
    EventPublisher, GatewayError, GatewayErrorCode, IngestRequest, MAX_ENVELOPE_BYTES,
    MAX_JETSTREAM_SUBJECT_BYTES, is_lowercase_uuidv7, is_scope_identifier,
};

pub struct JetStreamPublisher<T: JetStreamTransport> {
    transport: T,
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
