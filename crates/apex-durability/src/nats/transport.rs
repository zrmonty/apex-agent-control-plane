use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use super::client::NatsClient;
use super::config::NatsTlsConfig;
use crate::{
    GatewayError, GatewayErrorCode, JetStreamTransport, MAX_ENVELOPE_BYTES,
    MAX_JETSTREAM_SUBJECT_BYTES,
};

pub struct NatsJetStreamTransport<C: NatsClient> {
    client: C,
    config: NatsTlsConfig,
}

impl<C: NatsClient> NatsJetStreamTransport<C> {
    pub fn new(
        client: C,
        config: NatsTlsConfig,
        trusted_base: &Path,
    ) -> Result<Self, GatewayError> {
        let config = config.validated(trusted_base)?;
        Ok(Self { client, config })
    }

    pub fn config(&self) -> &NatsTlsConfig {
        &self.config
    }
}

impl<C: NatsClient> JetStreamTransport for NatsJetStreamTransport<C> {
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        validate_publish_request(subject, message_id, payload)?;
        match catch_unwind(AssertUnwindSafe(|| {
            self.client.publish(subject, message_id, payload)
        })) {
            Ok(result) => result,
            Err(_) => Err(GatewayError::internal()),
        }
    }
}

pub(crate) fn validate_publish_request(
    subject: &str,
    message_id: &str,
    payload: &[u8],
) -> Result<(), GatewayError> {
    if !valid_publish_subject(subject) || !valid_message_id(message_id) {
        return Err(GatewayError::invalid_nats_publish_request());
    }
    if payload.is_empty() {
        return Err(GatewayError::invalid_nats_publish_request());
    }
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
    }
    Ok(())
}

pub(crate) fn valid_publish_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_JETSTREAM_SUBJECT_BYTES
        && subject.split('.').all(|token| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

pub(crate) fn valid_message_id(message_id: &str) -> bool {
    !message_id.is_empty()
        && message_id.len() <= 256
        && message_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
