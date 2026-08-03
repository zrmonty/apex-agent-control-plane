use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use prost::Message;

use crate::{
    ArchivePublisher, ClickHousePublisher, DurableEventSink, GatewayError, GatewayErrorCode,
    IngestRequest, MAX_ENVELOPE_BYTES,
};

const MAX_HTTP_ENDPOINT_BYTES: usize = 512;
const MAX_BEARER_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHttpConfig {
    pub endpoint: String,
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub bearer_token_file: Option<PathBuf>,
}

impl AuthenticatedHttpConfig {
    pub fn build_client(
        &self,
        trusted_base: &Path,
    ) -> Result<(reqwest::blocking::Client, Option<String>), GatewayError> {
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| GatewayError::invalid_sink_configuration())?;
        if endpoint.scheme() != "https"
            || self.endpoint.len() > MAX_HTTP_ENDPOINT_BYTES
            || endpoint.host_str().is_none()
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path().to_ascii_lowercase().contains("%2f")
            || endpoint.path().to_ascii_lowercase().contains("%5c")
            || endpoint.path().to_ascii_lowercase().contains("%2e")
            || self
                .endpoint
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(GatewayError::invalid_sink_configuration());
        }
        if !safe_endpoint_host(&endpoint) {
            return Err(GatewayError::invalid_sink_configuration());
        }
        if trusted_base.is_symlink() {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let base = trusted_base
            .canonicalize()
            .map_err(|_| GatewayError::invalid_sink_configuration())?;
        if !base.is_dir() || base.is_symlink() {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let ca = read_secret(&self.ca_file, &base, false)?;
        let cert = read_secret(&self.client_cert_file, &base, false)?;
        let key = read_secret(&self.client_key_file, &base, true)?;
        let ca_path = canonical_secret_path(&self.ca_file, &base, false)?;
        let cert_path = canonical_secret_path(&self.client_cert_file, &base, false)?;
        let key_path = canonical_secret_path(&self.client_key_file, &base, true)?;
        if ca_path == cert_path || ca_path == key_path || cert_path == key_path {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let bearer_path = self
            .bearer_token_file
            .as_ref()
            .map(|path| canonical_secret_path(path, &base, true))
            .transpose()?;
        if bearer_path
            .as_ref()
            .is_some_and(|path| path == &ca_path || path == &cert_path || path == &key_path)
        {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let builder = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            // Sinks must never follow an endpoint-controlled redirect with client
            // credentials or mTLS identity attached.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .map_err(|_| GatewayError::invalid_sink_configuration())?,
            )
            .identity(
                reqwest::Identity::from_pem(&[cert.as_slice(), key.as_slice()].concat())
                    .map_err(|_| GatewayError::invalid_sink_configuration())?,
            );
        let token = self
            .bearer_token_file
            .as_ref()
            .map(|path| read_token(path, &base))
            .transpose()?;
        let client = builder.build().map_err(|_| GatewayError::internal())?;
        Ok((client, token))
    }
}

fn safe_endpoint_host(endpoint: &reqwest::Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return false;
    }
    let Ok(address) = normalized.parse::<IpAddr>() else {
        return normalized.len() <= 253
            && normalized
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
            && normalized
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    };
    match address {
        IpAddr::V4(value) => {
            !value.is_loopback()
                && !value.is_private()
                && !value.is_link_local()
                && !value.is_unspecified()
                && !value.is_broadcast()
        }
        IpAddr::V6(value) => {
            !value.is_loopback()
                && !value.is_unique_local()
                && !value.is_unicast_link_local()
                && !value.is_unspecified()
        }
    }
}

fn read_secret(path: &Path, base: &Path, private_key: bool) -> Result<Vec<u8>, GatewayError> {
    let canonical = canonical_secret_path(path, base, private_key)?;
    let file = fs::File::open(canonical).map_err(|_| GatewayError::invalid_sink_configuration())?;
    let mut bytes = Vec::with_capacity(1024 * 1024 + 1);
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GatewayError::invalid_sink_configuration())?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(bytes)
}

fn canonical_secret_path(
    path: &Path,
    base: &Path,
    _private_key: bool,
) -> Result<PathBuf, GatewayError> {
    if path.is_symlink() {
        return Err(GatewayError::invalid_sink_configuration());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| GatewayError::invalid_sink_configuration())?;
    if !canonical.starts_with(base) || !canonical.is_file() {
        return Err(GatewayError::invalid_sink_configuration());
    }
    let metadata =
        fs::metadata(&canonical).map_err(|_| GatewayError::invalid_sink_configuration())?;
    if metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        return Err(GatewayError::invalid_sink_configuration());
    }
    #[cfg(unix)]
    if _private_key {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GatewayError::invalid_sink_configuration());
        }
    }
    Ok(canonical)
}

fn read_token(path: &Path, base: &Path) -> Result<String, GatewayError> {
    let bytes = read_secret(path, base, true)?;
    let token = String::from_utf8(bytes).map_err(|_| GatewayError::invalid_sink_configuration())?;
    let token = token.trim().to_owned();
    if token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || !token.is_ascii()
        || token.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(token)
}

pub struct ClickHouseHttpPublisher {
    client: reqwest::blocking::Client,
    endpoint: String,
    bearer_token: Option<String>,
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
            request = request.bearer_auth(token);
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
    client: reqwest::blocking::Client,
    endpoint: String,
    bearer_token: Option<String>,
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
        let url = format!(
            "{}/{}.pb",
            self.endpoint.trim_end_matches('/'),
            event.event_id
        );
        let mut request = self
            .client
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header("If-None-Match", "*")
            .header("X-Apex-Event-Id", &event.event_id)
            .header("X-Apex-Event-Hash", &event_hash)
            .body(event.envelope.clone());
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
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

fn validate_sink_event(event: &IngestRequest) -> Result<String, GatewayError> {
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

fn response_event_hash_matches(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all("X-Apex-Event-Hash").iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.to_str().ok().is_some_and(|value| value == expected)
}

fn http_failure(status: reqwest::StatusCode) -> GatewayError {
    match status.as_u16() {
        400 | 413 => GatewayError::new(GatewayErrorCode::InvalidEnvelope),
        401 | 403 => GatewayError::invalid_sink_configuration(),
        409 => GatewayError::new(GatewayErrorCode::IdempotencyConflict),
        429 | 500..=599 => GatewayError::publish_failed(),
        _ => GatewayError::invalid_sink_configuration(),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::{
        canonical_secret_path, http_failure, read_secret, read_token, validate_sink_event,
    };
    use crate::{IngestRequest, proto};
    use prost::Message;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn valid_event() -> IngestRequest {
        let mut envelope = proto::EventEnvelope {
            event_id: "018f5c91-2d88-7c00-8000-000000000001".to_owned(),
            timestamp: "2024-02-29T23:59:59.000000Z".to_owned(),
            r#type: 1,
            agent_id: "agent".to_owned(),
            run_id: "run".to_owned(),
            parent_run_id: None,
            trace_id: "trace".to_owned(),
            scope: Some(proto::Scope {
                workspace_id: "workspace".to_owned(),
                namespace_id: "namespace".to_owned(),
                agent_group_ids: vec![],
            }),
            actor: Some(proto::Actor {
                r#type: 2,
                id: "agent".to_owned(),
            }),
            version: Some(proto::Version {
                agent_code: "code".to_owned(),
                prompt: "prompt".to_owned(),
                model: "model".to_owned(),
            }),
            data: Some(prost_types::Struct::default()),
            integrity: Some(proto::Integrity {
                prev_hash: None,
                event_hash: String::new(),
            }),
            schema_version: 1,
        };
        let hash = IngestRequest::canonical_hash_for_test(&envelope).unwrap();
        envelope.integrity.as_mut().unwrap().event_hash = hash;
        IngestRequest::new(
            envelope.event_id.clone(),
            "workspace",
            "namespace",
            envelope.encode_to_vec(),
        )
    }

    fn local_http_server(
        status: u16,
        response_headers: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let headers = response_headers.to_owned();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![0; 16 * 1024];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]).to_string();
            let response = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: 0\r\n{}\r\n",
                status, headers
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (endpoint, handle)
    }

    #[test]
    fn response_hash_requires_one_matching_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "X-Apex-Event-Hash",
            reqwest::header::HeaderValue::from_static("abc"),
        );
        assert!(super::response_event_hash_matches(&headers, "abc"));
        headers.append(
            "X-Apex-Event-Hash",
            reqwest::header::HeaderValue::from_static("abc"),
        );
        assert!(!super::response_event_hash_matches(&headers, "abc"));
    }

    #[test]
    fn sink_boundary_rejects_path_injection_event_ids() {
        let event = IngestRequest::new("../../secrets", "workspace", "namespace", vec![1]);
        assert!(validate_sink_event(&event).is_err());
    }

    #[test]
    fn sink_boundary_rejects_empty_and_oversized_payloads() {
        let empty = IngestRequest::new(
            "018f3d5e-7abc-7def-8abc-1234567890ab",
            "workspace",
            "namespace",
            Vec::new(),
        );
        assert_eq!(
            validate_sink_event(&empty).unwrap_err().code,
            crate::GatewayErrorCode::InvalidEnvelope
        );

        let oversized = IngestRequest::new(
            "018f3d5e-7abc-7def-8abc-1234567890ab",
            "workspace",
            "namespace",
            vec![0; crate::MAX_ENVELOPE_BYTES + 1],
        );
        assert_eq!(
            validate_sink_event(&oversized).unwrap_err().code,
            crate::GatewayErrorCode::PayloadTooLarge
        );
    }

    #[test]
    fn endpoint_validation_rejects_credential_and_routing_ambiguity() {
        let endpoints = [
            "http://clickhouse.internal/insert",
            "https://user:password@clickhouse.internal/insert",
            "https://clickhouse.internal/insert?token=secret",
            "https://clickhouse.internal/insert#fragment",
            "https://clickhouse.internal/api/%2fprivate",
            "https://clickhouse.internal/api/%2e%2e/private",
            "https:///missing-host",
            "https://localhost/v1/events",
            "https://127.0.0.1/v1/events",
            "https://10.0.0.12/v1/events",
            "https://[::1]/v1/events",
        ];
        for endpoint in endpoints {
            let config = crate::AuthenticatedHttpConfig {
                endpoint: endpoint.to_owned(),
                ca_file: "missing-ca.pem".into(),
                client_cert_file: "missing-cert.pem".into(),
                client_key_file: "missing-key.pem".into(),
                bearer_token_file: None,
            };
            assert!(
                config.build_client(std::path::Path::new(".")).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn sink_boundary_rejects_metadata_or_protobuf_mismatches() {
        let event = IngestRequest::new(
            "018f3d5e-7abc-7def-8abc-1234567890ab",
            "workspace",
            "namespace",
            vec![1, 2, 3],
        );
        let error = validate_sink_event(&event).unwrap_err();
        assert_eq!(error.code, crate::GatewayErrorCode::InvalidEnvelope);
        assert!(!error.retryable);
        assert!(!error.summary.is_empty());
        assert!(!error.cause.is_empty());
        assert!(!error.recommended_next_steps.is_empty());
        let report =
            error.diagnostic_report("event-ingest.http-sink", "workspace", "namespace", None);
        let handoff = report.to_ai_markdown();
        assert!(handoff.contains("INVALID_ENVELOPE"));
        assert!(handoff.contains("Recommended next steps"));
    }

    #[test]
    fn http_status_errors_preserve_terminal_and_retryable_semantics() {
        for status in [400, 401, 403, 409, 413] {
            assert!(!super::http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
        }
        for status in [429, 500, 502, 503] {
            assert!(super::http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
        }
        for status in [301, 302, 404, 408] {
            assert!(!super::http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
        }
    }

    #[test]
    fn http_status_mapping_is_bounded_and_explicit() {
        assert_eq!(
            http_failure(reqwest::StatusCode::BAD_REQUEST).code,
            crate::GatewayErrorCode::InvalidEnvelope
        );
        assert_eq!(
            http_failure(reqwest::StatusCode::UNAUTHORIZED).code,
            crate::GatewayErrorCode::InvalidSinkConfiguration
        );
        assert_eq!(
            http_failure(reqwest::StatusCode::CONFLICT).code,
            crate::GatewayErrorCode::IdempotencyConflict
        );
        assert!(http_failure(reqwest::StatusCode::TOO_MANY_REQUESTS).retryable);
        assert_eq!(
            http_failure(reqwest::StatusCode::NOT_FOUND).code,
            crate::GatewayErrorCode::InvalidSinkConfiguration
        );
    }

    #[test]
    fn token_reader_trims_only_safe_ascii_tokens() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "apex-http-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("token");
        std::fs::write(&path, "token-value\n").unwrap();
        let base = root.parent().unwrap();
        assert!(read_token(&path, base).is_err());
        std::fs::write(&path, "token value").unwrap();
        assert!(read_token(&path, base).is_err());
        std::fs::write(&path, vec![0xff]).unwrap();
        assert!(read_token(&path, base).is_err());
    }

    #[test]
    fn secret_reader_enforces_trusted_base_and_size() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("apex-http-secret-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("secret");
        std::fs::write(&path, b"secret").unwrap();
        let base = root.parent().unwrap();
        assert!(canonical_secret_path(&path, base, false).is_err());
        assert!(read_secret(&path, base, false).is_err());
        assert!(canonical_secret_path(&root.join("missing"), base, false).is_err());
        std::fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
        assert!(read_secret(&path, base, false).is_err());
    }

    #[test]
    fn publishers_use_local_http_server_for_success_and_failure_paths() {
        let event = valid_event();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let (endpoint, handle) = local_http_server(200, "");
        let mut clickhouse = super::ClickHouseHttpPublisher {
            client: client.clone(),
            endpoint,
            bearer_token: Some("test-token".to_owned()),
        };
        let result = crate::DurableEventSink::write_event(&mut clickhouse, &event);
        assert!(result.is_ok(), "{result:?}");
        let request = handle.join().unwrap();
        assert!(request.starts_with("POST "));
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower.contains("x-apex-event-id:"));
        assert!(request_lower.contains("authorization: bearer test-token"));

        let (endpoint, handle) = local_http_server(503, "");
        let mut clickhouse = super::ClickHouseHttpPublisher {
            client: client.clone(),
            endpoint,
            bearer_token: None,
        };
        assert_eq!(
            crate::DurableEventSink::write_event(&mut clickhouse, &event)
                .unwrap_err()
                .code,
            crate::GatewayErrorCode::PublishFailed
        );
        let _ = handle.join().unwrap();

        let event_hash = crate::proto::EventEnvelope::decode(event.envelope())
            .unwrap()
            .integrity
            .unwrap()
            .event_hash;
        let headers = format!("X-Apex-Event-Hash: {event_hash}\r\n");
        let (endpoint, handle) = local_http_server(412, &headers);
        let mut archive = super::ArchiveHttpPublisher {
            client,
            endpoint,
            bearer_token: None,
        };
        assert!(crate::DurableEventSink::write_event(&mut archive, &event).is_ok());
        let request = handle.join().unwrap();
        assert!(request.starts_with("PUT "));
        assert!(request.to_ascii_lowercase().contains("if-none-match: *"));
    }

    #[test]
    fn archive_receipt_mismatch_and_clickhouse_transport_failure_are_safe() {
        let event = valid_event();
        let (endpoint, handle) = local_http_server(412, "X-Apex-Event-Hash: wrong\r\n");
        let mut archive = super::ArchiveHttpPublisher {
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap(),
            endpoint,
            bearer_token: None,
        };
        assert_eq!(
            crate::DurableEventSink::write_event(&mut archive, &event)
                .unwrap_err()
                .code,
            crate::GatewayErrorCode::InvalidSinkConfiguration
        );
        let _ = handle.join().unwrap();

        let (endpoint, handle) = local_http_server(200, "");
        let mut archive = super::ArchiveHttpPublisher {
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap(),
            endpoint,
            bearer_token: None,
        };
        assert_eq!(
            crate::DurableEventSink::write_event(&mut archive, &event)
                .unwrap_err()
                .code,
            crate::GatewayErrorCode::InvalidSinkConfiguration
        );
        let _ = handle.join().unwrap();

        let mut clickhouse = super::ClickHouseHttpPublisher {
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap(),
            endpoint: "http://127.0.0.1:1".to_owned(),
            bearer_token: None,
        };
        assert_eq!(
            crate::DurableEventSink::write_event(&mut clickhouse, &event)
                .unwrap_err()
                .code,
            crate::GatewayErrorCode::PublishFailed
        );
    }
}
