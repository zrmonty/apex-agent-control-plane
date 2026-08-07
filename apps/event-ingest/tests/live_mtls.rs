//! Live mTLS handshake tests against Docker services from
//! `deploy/compose/live-mtls/`.
//!
//! Enabled only when `APEX_LIVE_MTLS=1` and secrets exist. Skipped otherwise so
//! unit CI stays offline-friendly.

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use apex_event_ingest::{
    ArchiveHttpPublisher, AsyncNatsJetStreamClient, AuthenticatedHttpConfig,
    ClickHouseHttpPublisher, DurableEventSink, IngestRequest, NatsClient, NatsTlsConfig,
};
use prost::Message;

fn live_enabled() -> bool {
    std::env::var("APEX_LIVE_MTLS").ok().as_deref() == Some("1")
}

fn install_rustls_provider() {
    // async-nats and redis both use rustls; pin a single process-level provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_LIVE_MTLS_SECRETS") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets")
}

fn require_secret(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS secret {name} under {}; run generate_pki.py + render_configs.py",
        root.display()
    );
    path
}

fn sample_event() -> IngestRequest {
    let event_id = "018f5c91-2d88-7c00-8000-0000000000aa";
    let mut envelope = apex_event_ingest::proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2024-02-29T23:59:59.000000Z".to_owned(),
        r#type: 1,
        agent_id: "agent".to_owned(),
        run_id: "run".to_owned(),
        parent_run_id: None,
        trace_id: "trace".to_owned(),
        scope: Some(apex_event_ingest::proto::Scope {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_group_ids: vec![],
        }),
        actor: Some(apex_event_ingest::proto::Actor {
            r#type: 2,
            id: "agent".to_owned(),
        }),
        version: Some(apex_event_ingest::proto::Version {
            agent_code: "code".to_owned(),
            prompt: "prompt".to_owned(),
            model: "model".to_owned(),
        }),
        data: Some(prost_types::Struct::default()),
        integrity: Some(apex_event_ingest::proto::Integrity {
            prev_hash: None,
            event_hash: String::new(),
        }),
        schema_version: 1,
    };
    envelope.integrity.as_mut().unwrap().event_hash =
        IngestRequest::canonical_hash_for_test(&envelope).unwrap();
    IngestRequest::new(event_id, "acme", "prod", envelope.encode_to_vec())
}

#[test]
fn live_valkey_mtls_rate_limit_and_fingerprint() {
    if !live_enabled() {
        eprintln!("skip live_valkey: set APEX_LIVE_MTLS=1");
        return;
    }
    install_rustls_provider();
    #[cfg(not(feature = "valkey"))]
    {
        panic!("live Valkey test requires --features valkey");
    }
    #[cfg(feature = "valkey")]
    {
        use apex_event_ingest::{
            EphemeralStore, FingerprintCounterKey, RateLimitKey, ValkeyConfig, ValkeyEphemeralStore,
        };
        let root = secrets_dir();
        let config = ValkeyConfig {
            host: std::env::var("APEX_LIVE_VALKEY_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("APEX_LIVE_VALKEY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16379),
            username: "apex-ingest".into(),
            password_file: require_secret(&root, "valkey-ingest-password"),
            ca_file: require_secret(&root, "ca.pem"),
            client_cert_file: require_secret(&root, "ingest-valkey-client.pem"),
            client_key_file: require_secret(&root, "ingest-valkey-client.key"),
            trusted_base: root.clone(),
        };
        let mut store =
            ValkeyEphemeralStore::connect(&config).expect("Valkey mTLS+ACL handshake must succeed");
        let key = RateLimitKey {
            namespace: "acme".into(),
            bucket: format!("live-{}", std::process::id()),
        };
        let first = store
            .check_rate_limit(&key, 2, Duration::from_secs(30))
            .expect("rate limit");
        assert!(first.allowed);
        let second = store
            .check_rate_limit(&key, 2, Duration::from_secs(30))
            .expect("rate limit");
        assert!(second.allowed);
        let third = store
            .check_rate_limit(&key, 2, Duration::from_secs(30))
            .expect("rate limit");
        assert!(!third.allowed);
        let fp = FingerprintCounterKey {
            namespace: "acme".into(),
            fingerprint_hex: format!("{:x}", std::process::id()),
        };
        assert_eq!(
            store
                .increment_fingerprint(&fp, Duration::from_secs(30))
                .unwrap(),
            1
        );
        assert_eq!(store.fingerprint_count(&fp).unwrap(), 1);
    }
}

#[test]
fn live_nats_mtls_publish_ack() {
    if !live_enabled() {
        eprintln!("skip live_nats: set APEX_LIVE_MTLS=1");
        return;
    }
    install_rustls_provider();
    let root = secrets_dir();
    let host = std::env::var("APEX_LIVE_NATS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("APEX_LIVE_NATS_PORT").unwrap_or_else(|_| "14222".into());
    let config = NatsTlsConfig {
        server_url: format!("tls://{host}:{port}"),
        ca_file: require_secret(&root, "ca.pem"),
        client_cert_file: require_secret(&root, "ingest-nats-client.pem"),
        client_key_file: require_secret(&root, "ingest-nats-client.key"),
        username_file: Some(require_secret(&root, "nats-username")),
        password_file: Some(require_secret(&root, "nats-password")),
    };
    let mut client = AsyncNatsJetStreamClient::connect(&config, &root)
        .expect("NATS mTLS+credentials handshake must succeed");

    // Ensure a stream exists for the publish subject.
    ensure_events_stream(&config, &root);

    client
        .publish(
            "apex.events.acme.prod",
            "018f5c91-2d88-7c00-8000-0000000000bb",
            b"live-mtls-payload",
        )
        .expect("JetStream publish must ack");
}

fn ensure_events_stream(config: &NatsTlsConfig, trusted_base: &Path) {
    use async_nats::jetstream::stream::Config as StreamConfig;

    config.validate(trusted_base).expect("nats config");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut options = async_nats::ConnectOptions::new()
            .require_tls(true)
            .tls_first()
            .connection_timeout(Duration::from_secs(5))
            .add_root_certificates(config.ca_file.clone())
            .add_client_certificate(
                config.client_cert_file.clone(),
                config.client_key_file.clone(),
            );
        if let (Some(user_file), Some(pass_file)) = (&config.username_file, &config.password_file) {
            let user = std::fs::read_to_string(user_file).unwrap();
            let pass = std::fs::read_to_string(pass_file).unwrap();
            options = options.user_and_password(user.trim().to_owned(), pass.trim().to_owned());
        }
        let client = options
            .connect(&config.server_url)
            .await
            .expect("nats connect for stream bootstrap");
        let js = async_nats::jetstream::new(client);
        let _ = js
            .get_or_create_stream(StreamConfig {
                name: "APEX_EVENTS".into(),
                subjects: vec!["apex.events.>".into()],
                ..Default::default()
            })
            .await
            .expect("create stream");
    });
}

#[test]
fn live_clickhouse_and_archive_provider_mtls() {
    if !live_enabled() {
        eprintln!("skip live_http_providers: set APEX_LIVE_MTLS=1");
        return;
    }
    let root = secrets_dir();
    let ch_host = std::env::var("APEX_LIVE_CH_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let ch_port = std::env::var("APEX_LIVE_CH_PORT").unwrap_or_else(|_| "18443".into());
    let ar_host = std::env::var("APEX_LIVE_ARCHIVE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let ar_port = std::env::var("APEX_LIVE_ARCHIVE_PORT").unwrap_or_else(|_| "18444".into());

    let ch_config = AuthenticatedHttpConfig {
        endpoint: format!("https://{ch_host}:{ch_port}/v1/events"),
        ca_file: require_secret(&root, "ca.pem"),
        client_cert_file: require_secret(&root, "ingest-http-client.pem"),
        client_key_file: require_secret(&root, "ingest-http-client.key"),
        bearer_token_file: None,
    };
    let mut clickhouse =
        ClickHouseHttpPublisher::new(ch_config, &root).expect("clickhouse client builds");
    let event = sample_event();
    clickhouse
        .write_event(&event)
        .expect("ClickHouse projection mTLS write must succeed");
    // Same hash replay is an ack (204).
    clickhouse
        .write_event(&event)
        .expect("same-hash duplicate must be acknowledged");

    let ar_config = AuthenticatedHttpConfig {
        endpoint: format!("https://{ar_host}:{ar_port}/v1/events"),
        ca_file: require_secret(&root, "ca.pem"),
        client_cert_file: require_secret(&root, "ingest-http-client.pem"),
        client_key_file: require_secret(&root, "ingest-http-client.key"),
        bearer_token_file: None,
    };
    let mut archive = ArchiveHttpPublisher::new(ar_config, &root).expect("archive client builds");
    archive
        .write_event(&event)
        .expect("archive provider mTLS write must succeed");
    // Identical replay is create-only 412 with matching hash header.
    archive
        .write_event(&event)
        .expect("identical archive replay must be accepted via hash match");
}

/// Cross-tenant Valkey key isolation, verified against the real server.
///
/// `is_scope_identifier` permits `:` inside a workspace or namespace, and `:`
/// is also the Valkey key separator. Interpolating components raw would let
/// `("a:b", "c")` and `("a", "b:c")` collapse onto one key, so one tenant could
/// spend another's admission budget or trip another's deny hint. The builder
/// hex-encodes each component; this proves the property end to end on a live
/// server rather than only at the formatting function.
#[test]
fn live_valkey_cross_tenant_keys_do_not_collide() {
    if !live_enabled() {
        eprintln!("skip live_valkey_cross_tenant_keys: set APEX_LIVE_MTLS=1");
        return;
    }
    install_rustls_provider();
    #[cfg(not(feature = "valkey"))]
    {
        panic!("live Valkey test requires --features valkey");
    }
    #[cfg(feature = "valkey")]
    {
        use apex_event_ingest::{EphemeralStore, RateLimitKey, ValkeyConfig, ValkeyEphemeralStore};

        let root = secrets_dir();
        let config = ValkeyConfig {
            host: std::env::var("APEX_LIVE_VALKEY_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("APEX_LIVE_VALKEY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16379),
            username: "apex-ingest".into(),
            password_file: require_secret(&root, "valkey-ingest-password"),
            ca_file: require_secret(&root, "ca.pem"),
            client_cert_file: require_secret(&root, "ingest-valkey-client.pem"),
            client_key_file: require_secret(&root, "ingest-valkey-client.key"),
            trusted_base: root.clone(),
        };
        let mut store = ValkeyEphemeralStore::connect(&config).expect("Valkey mTLS handshake");

        // Unique per run so repeated runs never inherit a previous window.
        let run = std::process::id();
        let tenant_a = RateLimitKey {
            namespace: format!("a{run}:b"),
            bucket: "c".into(),
        };
        let tenant_b = RateLimitKey {
            namespace: format!("a{run}"),
            bucket: "b:c".into(),
        };

        // Spend tenant A's entire budget.
        let limit = 2;
        let window = Duration::from_secs(30);
        for _ in 0..limit {
            assert!(
                store
                    .check_rate_limit(&tenant_a, limit, window)
                    .expect("tenant A rate limit")
                    .allowed
            );
        }
        assert!(
            !store
                .check_rate_limit(&tenant_a, limit, window)
                .expect("tenant A rate limit")
                .allowed,
            "tenant A must be limited once its own budget is spent"
        );

        // Tenant B shares no budget with tenant A despite the ambiguous split.
        assert!(
            store
                .check_rate_limit(&tenant_b, limit, window)
                .expect("tenant B rate limit")
                .allowed,
            "cross-tenant Valkey key collision: tenant B inherited tenant A's spent budget"
        );
    }
}
