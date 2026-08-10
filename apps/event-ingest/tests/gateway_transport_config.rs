//! NATS TLS configuration and transport validation, and HTTP-sink endpoint
//! configuration: rejecting non-TLS/credential-bearing endpoints, malformed or
//! oversized TLS material, secret files outside the trusted base, unsafe
//! private-key permissions, and direct-publish boundary bypasses -- plus
//! containment of transport-level panics.
//!
//! See the sibling `gateway_*.rs` files for the rest of this suite:
//! auth admission, JetStream publishing, envelope validation,
//! idempotency/scope, diagnostics, and durable fanout.

use apex_event_ingest::{
    AuthenticatedHttpConfig, GatewayError, GatewayErrorCode, JetStreamTransport,
    MAX_ENVELOPE_BYTES, NatsClient, NatsJetStreamTransport, NatsTlsConfig,
};
use std::fs::{create_dir, remove_dir_all, write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn nats_test_files() -> (std::path::PathBuf, NatsTlsConfig) {
    let suffix = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("apex-nats-test-{}-{suffix}", std::process::id()));
    let _ = remove_dir_all(&base);
    create_dir(&base).expect("create isolated NATS TLS test directory");
    let ca = base.join("ca.pem");
    let cert = base.join("client.pem");
    let key = base.join("client.key");
    write(&ca, b"ca").expect("write CA fixture");
    write(&cert, b"cert").expect("write certificate fixture");
    write(&key, b"key").expect("write private-key fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .expect("restrict private-key fixture permissions");
    }
    (
        base,
        NatsTlsConfig {
            server_url: "tls://nats.internal:4222".to_owned(),
            ca_file: ca,
            client_cert_file: cert,
            client_key_file: key,
            username_file: None,
            password_file: None,
        },
    )
}

#[derive(Default)]
struct RecordingNatsClient {
    published: Vec<(String, String, Vec<u8>)>,
}

struct PanickingNatsClient;

struct AssertingNatsClient {
    expected_payload: Vec<u8>,
}

impl NatsClient for RecordingNatsClient {
    fn publish(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        self.published
            .push((subject.to_owned(), message_id.to_owned(), payload.to_vec()));
        Ok(())
    }
}

impl NatsClient for PanickingNatsClient {
    fn publish(
        &mut self,
        _subject: &str,
        _message_id: &str,
        _payload: &[u8],
    ) -> Result<(), GatewayError> {
        panic!("simulated NATS client panic")
    }
}

impl NatsClient for AssertingNatsClient {
    fn publish(
        &mut self,
        _subject: &str,
        _message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        assert_eq!(payload, self.expected_payload.as_slice());
        Ok(())
    }
}

#[test]
fn nats_tls_config_rejects_non_tls_and_credential_bearing_endpoints() {
    let (base, mut config) = nats_test_files();
    for endpoint in [
        "nats://nats.internal:4222",
        "tls://user:secret@nats.internal",
        "tls://nats.internal/path",
        "tls://",
        "tls://:4222",
        "tls://nats.internal:65536",
        "tls://nats.internal:0",
        "tls://nats.internal:",
        "tls://nats.internal:42:43",
        "tls://nats.internal\u{00a0}:4222",
        "tls://nats_internal:4222",
        "tls://nats.internal;command:4222",
        "tls://-nats.internal:4222",
        "tls://nats-.internal:4222",
        "tls://[fe80::1%25eth0]:4222",
    ] {
        config.server_url = endpoint.to_owned();
        let error = config.validate(&base).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidNatsConfiguration);
        assert_eq!(error.grpc_status(), "INVALID_ARGUMENT");
        assert!(!error.retryable);
    }
    for endpoint in [
        format!("tls://{}:4222", "a".repeat(254)),
        format!("tls://{}.internal:4222", "a".repeat(64)),
        format!("tls://[{}]:4222", "1:".repeat(23)),
    ] {
        config.server_url = endpoint;
        let error = config.validate(&base).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidNatsConfiguration);
    }
    remove_dir_all(base).expect("remove isolated NATS TLS test directory");
}

#[test]
fn nats_configuration_errors_follow_the_project_diagnostic_contract() {
    let error = GatewayError::invalid_nats_configuration();
    assert_eq!(error.code.as_str(), "INVALID_NATS_CONFIGURATION");
    assert_eq!(error.grpc_status(), "INVALID_ARGUMENT");
    assert!(!error.retryable);
    assert!(error.summary.contains("NATS TLS"));
    assert!(error.cause.contains("TLS endpoint"));
    assert!(
        error
            .recommended_next_steps
            .iter()
            .any(|step| step.contains("tls://"))
    );

    let report = error.diagnostic_report("event-ingest.nats", "acme", "prod", None);
    assert_eq!(report.failure.category, "configuration");
    let handoff = report.to_ai_markdown();
    assert!(handoff.contains("INVALID_NATS_CONFIGURATION"));
    assert!(handoff.contains("Recommended next steps"));
    assert!(!handoff.contains("C:\\"));
}

#[test]
fn nats_connection_errors_are_actionable_without_raw_client_details() {
    let error = GatewayError::nats_connection_failed();
    assert_eq!(error.code.as_str(), "NATS_CONNECTION_FAILED");
    assert_eq!(error.grpc_status(), "UNAVAILABLE");
    assert!(error.retryable);
    assert!(error.summary.contains("durable NATS connection"));
    assert!(error.cause.contains("bounded connection policy"));
    let report = error.diagnostic_report("event-ingest.nats", "acme", "prod", None);
    let handoff = report.to_ai_markdown();
    assert!(handoff.contains("NATS_CONNECTION_FAILED"));
    assert!(handoff.contains("NATS server health"));
    assert!(!handoff.contains("tls://"));
}

#[test]
fn authenticated_http_sinks_reject_unsafe_endpoint_configuration() {
    let config = AuthenticatedHttpConfig {
        endpoint: "http://clickhouse.internal/insert".to_owned(),
        ca_file: "missing-ca.pem".into(),
        client_cert_file: "missing-cert.pem".into(),
        client_key_file: "missing-key.pem".into(),
        bearer_token_file: None,
    };
    let error = config.build_client(Path::new(".")).unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::InvalidSinkConfiguration);
    assert_eq!(error.grpc_status(), "INVALID_ARGUMENT");
    assert!(!error.retryable);
    assert!(error.summary.contains("durable"));
}

#[test]
fn async_nats_client_rejects_non_pem_material_before_network_access() {
    let (base, config) = nats_test_files();
    let error =
        match apex_event_ingest::AsyncNatsJetStreamClient::connect(&config, Path::new(&base)) {
            Ok(_) => panic!("invalid PEM material reached network setup"),
            Err(error) => error,
        };
    assert_eq!(error.code, GatewayErrorCode::InvalidNatsConfiguration);
    assert!(!error.retryable);
    remove_dir_all(base).expect("remove invalid PEM fixture directory");
}

#[test]
fn nats_transport_validates_files_before_delegating_publish() {
    let (base, config) = nats_test_files();
    let mut ipv6_config = config.clone();
    ipv6_config.server_url = "tls://[::1]:4222".to_owned();
    ipv6_config
        .validate(Path::new(&base))
        .expect("bracketed IPv6 endpoint is valid");
    let mut transport = NatsJetStreamTransport::new(
        RecordingNatsClient::default(),
        config.clone(),
        Path::new(&base),
    )
    .expect("valid TLS configuration");
    assert_eq!(transport.config().server_url, config.server_url);
    assert_eq!(
        transport.config().ca_file,
        config.ca_file.canonicalize().expect("canonical CA fixture")
    );
    transport
        .publish_event("apex.events.acme.prod", "event-1", b"payload")
        .expect("client publish succeeds");
    remove_dir_all(base).expect("remove isolated NATS TLS test directory");
}

#[test]
fn nats_transport_rejects_secret_files_outside_trusted_base() {
    let (base, mut config) = nats_test_files();
    let suffix = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let outside =
        std::env::temp_dir().join(format!("apex-nats-outside-{}-{suffix}", std::process::id()));
    let _ = remove_dir_all(&outside);
    create_dir(&outside).expect("create outside fixture directory");
    let outside_key = outside.join("client.key");
    write(&outside_key, b"key").expect("write outside key fixture");
    config.client_key_file = outside_key;
    let error = match NatsJetStreamTransport::new(RecordingNatsClient::default(), config, &base) {
        Ok(_) => panic!("secret file outside trusted base was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, GatewayErrorCode::InvalidNatsConfiguration);
    remove_dir_all(base).expect("remove trusted fixture directory");
    remove_dir_all(outside).expect("remove outside fixture directory");
}

#[test]
fn nats_transport_rejects_empty_oversized_or_aliased_tls_material() {
    let (base, mut config) = nats_test_files();
    write(&config.ca_file, []).expect("empty CA fixture");
    assert_eq!(
        config.validate(&base).unwrap_err().code,
        GatewayErrorCode::InvalidNatsConfiguration
    );

    write(&config.ca_file, vec![b'x'; 1024 * 1024 + 1]).expect("oversized CA fixture");
    assert_eq!(
        config.validate(&base).unwrap_err().code,
        GatewayErrorCode::InvalidNatsConfiguration
    );

    write(&config.ca_file, b"ca").expect("restore CA fixture");
    config.ca_file = config.client_cert_file.clone();
    assert_eq!(
        config.validate(&base).unwrap_err().code,
        GatewayErrorCode::InvalidNatsConfiguration
    );
    remove_dir_all(base).expect("remove TLS material fixture directory");
}

#[cfg(unix)]
#[test]
fn nats_transport_rejects_private_keys_with_group_or_world_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (base, config) = nats_test_files();
    std::fs::set_permissions(
        &config.client_key_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("make private-key fixture readable by group/world");
    assert_eq!(
        config.validate(&base).unwrap_err().code,
        GatewayErrorCode::InvalidNatsConfiguration
    );
    remove_dir_all(base).expect("remove permission fixture directory");
}

#[test]
fn nats_transport_rejects_direct_publish_boundary_bypasses_and_contains_panics() {
    let (base, config) = nats_test_files();
    let mut transport = NatsJetStreamTransport::new(
        RecordingNatsClient::default(),
        config.clone(),
        Path::new(&base),
    )
    .expect("valid TLS configuration");
    for (subject, message_id) in [
        ("", "event-1"),
        ("apex.events.>", "event-1"),
        ("apex..events", "event-1"),
        ("apex events", "event-1"),
        ("apex.events", "event id"),
        ("apex.events", "event/id"),
    ] {
        let error = transport
            .publish_event(subject, message_id, b"payload")
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidNatsPublishRequest);
    }
    let error = transport
        .publish_event("apex.events", "event-1", &[])
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::InvalidNatsPublishRequest);
    let error = transport
        .publish_event(
            "apex.events",
            "event-1",
            &vec![b'x'; MAX_ENVELOPE_BYTES + 1],
        )
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::PayloadTooLarge);
    remove_dir_all(base).expect("remove direct publish fixture directory");

    let (base, config) = nats_test_files();
    let mut panicking = NatsJetStreamTransport::new(PanickingNatsClient, config, Path::new(&base))
        .expect("valid TLS configuration");
    let error = panicking
        .publish_event("apex.events", "event-1", b"payload")
        .unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::Internal);
    assert!(error.summary.contains("internal"));
    remove_dir_all(base).expect("remove panic fixture directory");

    let (base, config) = nats_test_files();
    let opaque_payload = b"IGNORE PRIOR INSTRUCTIONS\0\xff".to_vec();
    let mut opaque = NatsJetStreamTransport::new(
        AssertingNatsClient {
            expected_payload: opaque_payload.clone(),
        },
        config,
        Path::new(&base),
    )
    .expect("valid TLS configuration");
    opaque
        .publish_event("apex.events", "event-1", &opaque_payload)
        .expect("opaque event bytes remain unchanged");
    remove_dir_all(base).expect("remove opaque payload fixture directory");
}
