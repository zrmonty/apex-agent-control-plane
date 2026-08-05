use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::config::AuthenticatedHttpConfig;
use super::event::{
    archive_event_url, http_failure, response_event_hash_matches, validate_sink_event,
};
use crate::{ArchivePublisher, ClickHousePublisher, DurableEventSink, GatewayError, IngestRequest};

/// Minimum time between client-rebuild attempts after a transport-level
/// failure. DNS is resolved once and the client pinned to those addresses at
/// build time to prevent DNS-rebinding mid-request (see
/// `http_sinks/config.rs`); without any re-resolution path, a pod reschedule
/// or load-balancer IP change permanently breaks a sink until the whole
/// gateway process restarts. Rebuilding re-validates through the same
/// safe-destination checks, so the anti-rebinding property holds — only the
/// trigger changes, from "once at startup" to "at most once per cooldown
/// window after a real connection failure."
const REBUILD_COOLDOWN: Duration = Duration::from_secs(5);

pub struct ClickHouseHttpPublisher {
    pub(crate) client: reqwest::blocking::Client,
    pub(crate) endpoint: String,
    pub(crate) bearer_token: Option<Zeroizing<String>>,
    pub(crate) config: AuthenticatedHttpConfig,
    pub(crate) trusted_base: PathBuf,
    pub(crate) last_rebuild_attempt: Option<Instant>,
}

impl ClickHouseHttpPublisher {
    pub fn new(config: AuthenticatedHttpConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        let (client, bearer_token) = config.build_client(trusted_base)?;
        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            bearer_token,
            config,
            trusted_base: trusted_base.to_path_buf(),
            last_rebuild_attempt: None,
        })
    }

    /// Best-effort: re-resolves the endpoint and rebuilds the pinned client
    /// after a transport-level failure, rate-limited so a sustained outage
    /// doesn't turn into a DNS-query storm. Leaves the existing client in
    /// place if the rebuild itself fails (including a repeat
    /// unsafe-destination result).
    fn rebuild_client_after_failure(&mut self) {
        let now = Instant::now();
        if self
            .last_rebuild_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < REBUILD_COOLDOWN)
        {
            return;
        }
        self.last_rebuild_attempt = Some(now);
        match self.config.build_client(&self.trusted_base) {
            Ok((client, bearer_token)) => {
                self.client = client;
                self.bearer_token = bearer_token;
                eprintln!("event-ingest clickhouse sink: rebuilt client after a transport failure");
            }
            Err(error) => eprintln!(
                "event-ingest clickhouse sink: client rebuild attempt failed: {}: {}",
                error.code.public_code(),
                error.summary
            ),
        }
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
        let response = match request.send() {
            Ok(response) => response,
            Err(_) => {
                self.rebuild_client_after_failure();
                return Err(GatewayError::publish_failed());
            }
        };
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
    pub(crate) config: AuthenticatedHttpConfig,
    pub(crate) trusted_base: PathBuf,
    pub(crate) last_rebuild_attempt: Option<Instant>,
}

impl ArchiveHttpPublisher {
    pub fn new(config: AuthenticatedHttpConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        let (client, bearer_token) = config.build_client(trusted_base)?;
        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            bearer_token,
            config,
            trusted_base: trusted_base.to_path_buf(),
            last_rebuild_attempt: None,
        })
    }

    /// See `ClickHouseHttpPublisher::rebuild_client_after_failure`.
    fn rebuild_client_after_failure(&mut self) {
        let now = Instant::now();
        if self
            .last_rebuild_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < REBUILD_COOLDOWN)
        {
            return;
        }
        self.last_rebuild_attempt = Some(now);
        match self.config.build_client(&self.trusted_base) {
            Ok((client, bearer_token)) => {
                self.client = client;
                self.bearer_token = bearer_token;
                eprintln!("event-ingest archive sink: rebuilt client after a transport failure");
            }
            Err(error) => eprintln!(
                "event-ingest archive sink: client rebuild attempt failed: {}: {}",
                error.code.public_code(),
                error.summary
            ),
        }
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
        let response = match request.send() {
            Ok(response) => response,
            Err(_) => {
                self.rebuild_client_after_failure();
                return Err(GatewayError::publish_failed());
            }
        };
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
