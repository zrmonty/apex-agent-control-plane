use super::AuthenticatedHttpConfig;
use super::event::{
    archive_event_url, http_failure, response_event_hash_matches, validate_sink_event,
};
use super::publishers::{ArchiveHttpPublisher, ClickHouseHttpPublisher};
use super::secrets::{canonical_secret_path, read_secret, read_token};
use crate::{DurableEventSink, IngestRequest, proto};
use prost::Message;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

/// These tests construct publishers directly against a local plaintext test
/// server, bypassing `new()`/`build_client()`'s mTLS and DNS-safety
/// validation entirely. This placeholder config is never used to actually
/// build a client here — it only exists to satisfy the struct shape needed
/// for a same-instance rebuild attempt after a transport failure, which is
/// expected to fail closed (leaving the explicitly-constructed test client
/// untouched) against this bogus config.
fn placeholder_config(endpoint: &str) -> AuthenticatedHttpConfig {
    AuthenticatedHttpConfig {
        endpoint: endpoint.to_owned(),
        ca_file: PathBuf::new(),
        client_cert_file: PathBuf::new(),
        client_key_file: PathBuf::new(),
        bearer_token_file: None,
    }
}

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

fn ensure_rustls_provider() {
    // reqwest is built with `rustls-no-provider`; install ring before any Client::build.
    crate::install_rustls_provider();
}

fn http_client() -> reqwest::blocking::Client {
    ensure_rustls_provider();
    reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("test HTTP client")
}

fn local_http_server(status: u16, response_headers: &str) -> (String, thread::JoinHandle<String>) {
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
    assert!(response_event_hash_matches(&headers, "abc"));
    headers.append(
        "X-Apex-Event-Hash",
        reqwest::header::HeaderValue::from_static("abc"),
    );
    assert!(!response_event_hash_matches(&headers, "abc"));
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
        let config = AuthenticatedHttpConfig {
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
    let report = error.diagnostic_report("event-ingest.http-sink", "workspace", "namespace", None);
    let handoff = report.to_ai_markdown();
    assert!(handoff.contains("INVALID_ENVELOPE"));
    assert!(handoff.contains("Recommended next steps"));
}

#[test]
fn http_status_errors_preserve_terminal_and_retryable_semantics() {
    for status in [400, 401, 403, 409, 413] {
        assert!(!http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
    }
    for status in [429, 500, 502, 503] {
        assert!(http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
    }
    for status in [301, 302, 404, 408] {
        assert!(!http_failure(reqwest::StatusCode::from_u16(status).unwrap()).retryable);
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
fn archive_url_is_path_segment_safe_and_rejects_invalid_event_ids() {
    let url = archive_event_url(
        "https://archive.internal/v1/events",
        "018f5c91-2d88-7c00-8000-000000000001",
    )
    .unwrap();
    assert!(url.ends_with("/018f5c91-2d88-7c00-8000-000000000001.pb"));
    assert!(archive_event_url("https://archive.internal/v1/events", "../secret").is_err());
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
    // Canonicalize the trusted base so Path::starts_with matches on Linux and
    // Windows (Windows canonicalize may add a \\?\ prefix).
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "apex-http-secret-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let base = root.canonicalize().unwrap();
    let path = root.join("secret");
    std::fs::write(&path, b"secret").unwrap();

    // Outside the trusted base must fail.
    let outside_root = root.parent().unwrap().join(format!(
        "apex-http-secret-outside-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&outside_root).unwrap();
    let outside = outside_root.join("secret");
    std::fs::write(&outside, b"secret").unwrap();
    assert!(canonical_secret_path(&outside, &base, false).is_err());
    assert!(read_secret(&outside, &base, false).is_err());

    // Inside the base with a small file must succeed.
    assert!(canonical_secret_path(&path, &base, false).is_ok());
    assert_eq!(read_secret(&path, &base, false).unwrap(), b"secret");

    // Missing path fails.
    assert!(canonical_secret_path(&root.join("missing"), &base, false).is_err());

    // Oversize content fails.
    std::fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
    assert!(read_secret(&path, &base, false).is_err());

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside_root);
}

#[test]
fn secret_reader_private_key_gate_matches_the_permissions_primitive() {
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "apex-http-secret-private-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let base = root.canonicalize().unwrap();
    let key_path = root.join("key.pem");
    std::fs::write(&key_path, b"private-key-material").unwrap();
    let canonical = key_path.canonicalize().unwrap();

    // Whatever this platform's default permissions/ACL happen to be, the
    // private-key branch must agree exactly with the underlying permissions
    // primitive -- not silently ignore it either way.
    let restricted = crate::permissions::private_key_permissions_restricted(&canonical);
    assert_eq!(
        canonical_secret_path(&key_path, &base, true).is_ok(),
        restricted
    );
    assert_eq!(read_secret(&key_path, &base, true).is_ok(), restricted);
    // The same file is always fine when it isn't being treated as a private key.
    assert!(canonical_secret_path(&key_path, &base, false).is_ok());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn publishers_use_local_http_server_for_success_and_failure_paths() {
    let event = valid_event();
    let client = http_client();
    let (endpoint, handle) = local_http_server(200, "");
    let mut clickhouse = ClickHouseHttpPublisher {
        client: client.clone(),
        config: placeholder_config(&endpoint),
        endpoint,
        bearer_token: Some("test-token".to_owned().into()),
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    let result = DurableEventSink::write_event(&mut clickhouse, &event);
    assert!(result.is_ok(), "{result:?}");
    let request = handle.join().unwrap();
    assert!(request.starts_with("POST "));
    let request_lower = request.to_ascii_lowercase();
    assert!(request_lower.contains("x-apex-event-id:"));
    assert!(request_lower.contains("authorization: bearer test-token"));
    // Phase 0.6 item 4: the ClickHouse sink must ask for server-side async
    // batching on every insert, and must keep waiting for that insert to
    // actually land (so a failure is still reported to this caller, which is
    // what lets a failed insert reschedule instead of silently dropping).
    let request_line = request.lines().next().unwrap();
    assert!(
        request_line.contains("async_insert=1"),
        "request line must carry async_insert=1: {request_line}"
    );
    assert!(
        request_line.contains("wait_for_async_insert=1"),
        "request line must carry wait_for_async_insert=1: {request_line}"
    );

    let (endpoint, handle) = local_http_server(503, "");
    let mut clickhouse = ClickHouseHttpPublisher {
        client: client.clone(),
        config: placeholder_config(&endpoint),
        endpoint,
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert_eq!(
        DurableEventSink::write_event(&mut clickhouse, &event)
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
    let mut archive = ArchiveHttpPublisher {
        client,
        config: placeholder_config(&endpoint),
        endpoint,
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert!(DurableEventSink::write_event(&mut archive, &event).is_ok());
    let request = handle.join().unwrap();
    assert!(request.starts_with("PUT "));
    assert!(request.to_ascii_lowercase().contains("if-none-match: *"));
}

#[test]
fn archive_receipt_mismatch_and_clickhouse_transport_failure_are_safe() {
    let event = valid_event();
    let (endpoint, handle) = local_http_server(412, "X-Apex-Event-Hash: wrong\r\n");
    let mut archive = ArchiveHttpPublisher {
        client: http_client(),
        config: placeholder_config(&endpoint),
        endpoint,
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert_eq!(
        DurableEventSink::write_event(&mut archive, &event)
            .unwrap_err()
            .code,
        crate::GatewayErrorCode::InvalidSinkConfiguration
    );
    let _ = handle.join().unwrap();

    let (endpoint, handle) = local_http_server(200, "");
    let mut archive = ArchiveHttpPublisher {
        client: http_client(),
        config: placeholder_config(&endpoint),
        endpoint,
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert_eq!(
        DurableEventSink::write_event(&mut archive, &event)
            .unwrap_err()
            .code,
        crate::GatewayErrorCode::InvalidSinkConfiguration
    );
    let _ = handle.join().unwrap();

    let mut clickhouse = ClickHouseHttpPublisher {
        client: http_client(),
        config: placeholder_config("http://127.0.0.1:1"),
        endpoint: "http://127.0.0.1:1".to_owned(),
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert_eq!(
        DurableEventSink::write_event(&mut clickhouse, &event)
            .unwrap_err()
            .code,
        crate::GatewayErrorCode::PublishFailed
    );
}

#[test]
fn transport_failure_triggers_a_rate_limited_client_rebuild_attempt() {
    let event = valid_event();
    let mut clickhouse = ClickHouseHttpPublisher {
        client: http_client(),
        config: placeholder_config("http://127.0.0.1:1"),
        endpoint: "http://127.0.0.1:1".to_owned(),
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert!(clickhouse.last_rebuild_attempt.is_none());
    let _ = DurableEventSink::write_event(&mut clickhouse, &event);
    let first_attempt = clickhouse
        .last_rebuild_attempt
        .expect("a transport failure must record a rebuild attempt");
    // A second failure immediately after must be rate-limited: the cooldown
    // window means the timestamp does not advance to a fresh `Instant::now()`.
    let _ = DurableEventSink::write_event(&mut clickhouse, &event);
    assert_eq!(clickhouse.last_rebuild_attempt, Some(first_attempt));

    let mut archive = ArchiveHttpPublisher {
        client: http_client(),
        config: placeholder_config("http://127.0.0.1:1"),
        endpoint: "http://127.0.0.1:1".to_owned(),
        bearer_token: None,
        trusted_base: PathBuf::new(),
        last_rebuild_attempt: None,
    };
    assert!(archive.last_rebuild_attempt.is_none());
    let _ = DurableEventSink::write_event(&mut archive, &event);
    assert!(archive.last_rebuild_attempt.is_some());
}
