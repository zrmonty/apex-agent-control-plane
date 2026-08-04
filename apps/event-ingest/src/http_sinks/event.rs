use prost::Message;

use crate::{GatewayError, GatewayErrorCode, IngestRequest, MAX_ENVELOPE_BYTES};

pub(crate) fn validate_sink_event(event: &IngestRequest) -> Result<String, GatewayError> {
    // This check is intentionally repeated here because DurableEventSink is a
    // public seam and test/support constructors do not imply transport admission.
    if !crate::is_lowercase_uuidv7(&event.event_id) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
    }
    if event.envelope.is_empty() {
        return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
    }
    if event.envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
    }
    if !crate::is_scope_identifier(&event.workspace_id)
        || !crate::is_scope_identifier(&event.namespace_id)
        || event.scope_key() != format!("{}/{}", event.workspace_id, event.namespace_id)
    {
        return Err(GatewayError::new(GatewayErrorCode::ScopeDenied));
    }

    let envelope = crate::proto::EventEnvelope::decode(event.envelope.as_slice())
        .map_err(|_| GatewayError::new(GatewayErrorCode::InvalidEnvelope))?;
    let event_hash = envelope
        .integrity
        .as_ref()
        .map(|integrity| integrity.event_hash.clone())
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidIntegrity))?;
    let validated = IngestRequest::from_validated_transport(envelope)?;
    if validated.event_id != event.event_id
        || validated.workspace_id != event.workspace_id
        || validated.namespace_id != event.namespace_id
        || validated.envelope != event.envelope
    {
        return Err(GatewayError::new(GatewayErrorCode::InvalidEnvelope));
    }
    Ok(event_hash)
}

pub(crate) fn response_event_hash_matches(
    headers: &reqwest::header::HeaderMap,
    expected: &str,
) -> bool {
    let mut values = headers.get_all("X-Apex-Event-Hash").iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.to_str().ok().is_some_and(|value| value == expected)
}

pub(crate) fn archive_event_url(endpoint: &str, event_id: &str) -> Result<String, GatewayError> {
    if !crate::is_lowercase_uuidv7(event_id) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
    }
    let mut url =
        reqwest::Url::parse(endpoint).map_err(|_| GatewayError::invalid_sink_configuration())?;
    url.path_segments_mut()
        .map_err(|_| GatewayError::invalid_sink_configuration())?
        .push(&format!("{event_id}.pb"));
    Ok(url.to_string())
}

pub(crate) fn http_failure(status: reqwest::StatusCode) -> GatewayError {
    match status.as_u16() {
        400 | 413 => GatewayError::new(GatewayErrorCode::InvalidEnvelope),
        401 | 403 => GatewayError::invalid_sink_configuration(),
        409 => GatewayError::new(GatewayErrorCode::IdempotencyConflict),
        429 | 500..=599 => GatewayError::publish_failed(),
        _ => GatewayError::invalid_sink_configuration(),
    }
}
