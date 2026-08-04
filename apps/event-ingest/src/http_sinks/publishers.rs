use std::path::Path;
use zeroize::Zeroizing;

use super::config::AuthenticatedHttpConfig;
use super::event::{
    archive_event_url, http_failure, response_event_hash_matches, validate_sink_event,
};
use crate::{ArchivePublisher, ClickHousePublisher, DurableEventSink, GatewayError, IngestRequest};

pub struct ClickHouseHttpPublisher {
    pub(crate) client: reqwest::blocking::Client,
    pub(crate) endpoint: String,
    pub(crate) bearer_token: Option<Zeroizing<String>>,
}

impl ClickHouseHttpPublisher {
    pub fn new(config: AuthenticatedHttpConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        let (client, bearer_token) = config.build_client(trusted_base)?;
        Ok(Self {
            client,
            endpoint: config.endpoint,
            bearer_token,
        })
    }
}

impl DurableEventSink for ClickHouseHttpPublisher {
    fn write_event(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        let event_hash = validate_sink_event(event)?;
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(event.envelope.clone())
            .header("X-Apex-Event-Id", &event.event_id)
            .header("X-Apex-Event-Hash", &event_hash);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token.as_str());
        }
        let response = request.send().map_err(|_| GatewayError::publish_failed())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(http_failure(response.status()))
        }
    }
}

impl ClickHousePublisher for ClickHouseHttpPublisher {}

pub struct ArchiveHttpPublisher {
    pub(crate) client: reqwest::blocking::Client,
    pub(crate) endpoint: String,
    pub(crate) bearer_token: Option<Zeroizing<String>>,
}

impl ArchiveHttpPublisher {
    pub fn new(config: AuthenticatedHttpConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        let (client, bearer_token) = config.build_client(trusted_base)?;
        Ok(Self {
            client,
            endpoint: config.endpoint,
            bearer_token,
        })
    }
}

impl DurableEventSink for ArchiveHttpPublisher {
    fn write_event(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        let event_hash = validate_sink_event(event)?;
        let url = archive_event_url(&self.endpoint, &event.event_id)?;
        let mut request = self
            .client
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header("If-None-Match", "*")
            .header("X-Apex-Event-Id", &event.event_id)
            .header("X-Apex-Event-Hash", &event_hash)
            .body(event.envelope.clone());
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token.as_str());
        }
        let response = request.send().map_err(|_| GatewayError::publish_failed())?;
        if response.status().is_success() || response.status().as_u16() == 412 {
            if response_event_hash_matches(response.headers(), &event_hash) {
                return Ok(());
            }
            Err(GatewayError::invalid_sink_configuration())
        } else {
            Err(http_failure(response.status()))
        }
    }
}

impl ArchivePublisher for ArchiveHttpPublisher {}
