//! Startup-policy tests.
//!
//! These cover the parts of process wiring that encode a security decision --
//! bind policy, credential-source ambiguity, and the bounded/path-confined
//! secret reader the TLS material goes through -- rather than the `env::var`
//! plumbing around them, which this crate's `unsafe_code = "forbid"` makes
//! structurally untestable (Rust 2024 requires `unsafe` for `env::set_var`).

use std::fs;
use std::path::{Path, PathBuf};

use super::env::{
    DEFAULT_BIND_ADDR, OperatorTokenSource, control_postgres_url_value, fanout_interval_value,
    nats_retry_attempts_value, operator_token_source_value, resolve_bind_addr_value,
};
use super::secrets::{read_bounded, read_credential_table, trusted_secret_path};

fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "apex-control-startup-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn bind_address_defaults_to_loopback_and_refuses_silent_exposure() {
    assert_eq!(
        resolve_bind_addr_value(None, None).unwrap().to_string(),
        DEFAULT_BIND_ADDR
    );
    assert_eq!(
        resolve_bind_addr_value(Some(""), None).unwrap().to_string(),
        DEFAULT_BIND_ADDR
    );
    // Loopback needs no acknowledgement, in either address family.
    assert!(resolve_bind_addr_value(Some("127.0.0.1:9443"), None).is_ok());
    assert!(resolve_bind_addr_value(Some("[::1]:9443"), None).is_ok());

    // Anything else does, even though the listener now terminates mTLS.
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("[::]:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("10.0.0.5:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), Some("true")).is_ok());
}

#[test]
fn nonlocal_bind_acknowledgement_is_exact_and_fails_closed() {
    // A near-miss must never be read as consent to expose the control
    // channel. Only the literal "true" acknowledges.
    for near_miss in ["TRUE", "True", "1", "yes", "on", " true", "true ", ""] {
        assert!(
            resolve_bind_addr_value(Some("0.0.0.0:9443"), Some(near_miss)).is_err(),
            "{near_miss:?} must not acknowledge a non-loopback bind"
        );
    }
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), Some("false")).is_err());
}

#[test]
fn bind_address_rejects_values_that_are_not_socket_addresses() {
    for bad in [
        "9443",
        "127.0.0.1",
        "not-an-address",
        "localhost:9443",
        "::1:9443",
    ] {
        assert!(
            resolve_bind_addr_value(Some(bad), Some("true")).is_err(),
            "{bad:?} must not parse as a bind address"
        );
    }
}

#[test]
fn operator_token_source_refuses_two_configured_credential_sources() {
    assert_eq!(
        operator_token_source_value(None, None).unwrap(),
        OperatorTokenSource::Unset
    );
    assert_eq!(
        operator_token_source_value(Some("/run/secrets/tokens"), None).unwrap(),
        OperatorTokenSource::File(PathBuf::from("/run/secrets/tokens"))
    );
    assert_eq!(
        operator_token_source_value(None, Some("token-value|acme/prod")).unwrap(),
        OperatorTokenSource::Inline("token-value|acme/prod".to_owned())
    );
    // Both set: one of them would be silently ignored. Fail closed instead.
    assert!(operator_token_source_value(Some("/run/secrets/tokens"), Some("t|*")).is_err());
}

#[test]
fn bounded_reads_reject_empty_and_oversized_secret_material() {
    let root = scratch("bounded");
    let file = root.join("material");

    fs::write(&file, b"pem-bytes").unwrap();
    assert_eq!(read_bounded(&file, 32, "material").unwrap(), b"pem-bytes");

    fs::write(&file, b"").unwrap();
    assert!(read_bounded(&file, 32, "material").is_err());

    fs::write(&file, vec![b'a'; 33]).unwrap();
    assert!(read_bounded(&file, 32, "material").is_err());
    // Exactly at the limit is still accepted.
    assert!(read_bounded(&file, 33, "material").is_ok());

    assert!(read_bounded(&root.join("missing"), 32, "material").is_err());
}

#[test]
fn credential_table_reader_allows_multiline_entries_but_not_binary() {
    let root = scratch("table");
    let file = root.join("tokens");

    // One entry per line is the shape a human maintains, and
    // `parse_operator_token_table` trims each `;`-separated entry, so the
    // reader must not reject the newlines the way a single-token reader would.
    let table = "operator-token-aaaaaaaa|acme/prod;\noperator-token-bbbbbbbb|*;\n";
    fs::write(&file, table).unwrap();
    let raw = read_credential_table(&file, 4096, "tokens").unwrap();
    assert_eq!(raw, table);
    let resolver = apex_control_plane_api::parse_operator_token_table(&raw).unwrap();
    // Round-trips into a usable table, not just a readable string.
    drop(resolver);

    fs::write(&file, b"token|acme/prod\x00").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
    fs::write(&file, "token|acme/pröd").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
    fs::write(&file, "   \n\t  ").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
}

#[test]
fn trusted_secret_path_confines_material_to_the_trusted_base() {
    let root = scratch("trusted");
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();
    let inside = base.join("server.pem");
    fs::write(&inside, b"pem").unwrap();

    assert!(trusted_secret_path(&inside, &base, 4096, false, "cert").is_ok());

    // Outside the base, an empty file, an oversized file, a directory, and a
    // missing base are each refused.
    let outside = root.join("elsewhere.pem");
    fs::write(&outside, b"pem").unwrap();
    assert!(trusted_secret_path(&outside, &base, 4096, false, "cert").is_err());

    let empty = base.join("empty.pem");
    fs::write(&empty, b"").unwrap();
    assert!(trusted_secret_path(&empty, &base, 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&inside, &base, 2, false, "cert").is_err());
    assert!(trusted_secret_path(&base, &base, 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&inside, &root.join("absent"), 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&base.join("missing.pem"), &base, 4096, false, "cert").is_err());
}

#[test]
fn trusted_secret_path_defers_to_the_platform_private_key_permission_check() {
    let root = scratch("private");
    let key = root.join("server.key");
    fs::write(&key, b"private-key-material").unwrap();
    let canonical = key.canonicalize().unwrap();

    // Whatever this platform's default permissions/ACL happen to be, the
    // `private` branch must agree exactly with the shared permissions
    // primitive rather than silently ignoring it in either direction. Same
    // assertion `event-ingest`'s startup tests make about its own copy.
    let restricted = apex_event_ingest::permissions::private_key_permissions_restricted(&canonical);
    assert_eq!(
        trusted_secret_path(&key, &root, 4096, true, "key").is_ok(),
        restricted
    );
    assert!(trusted_secret_path(&key, &root, 4096, false, "key").is_ok());
}

#[test]
fn trusted_secret_path_refuses_a_symlinked_secret() {
    let root = scratch("symlink");
    let target = root.join("real.pem");
    fs::write(&target, b"pem").unwrap();
    let link = root.join("link.pem");
    if !create_symlink(&target, &link) {
        // Unprivileged Windows without Developer Mode cannot create symlinks;
        // the check itself is platform-independent, so skip rather than
        // assert on the host's privilege level.
        eprintln!("skip symlink case: this host does not permit symlink creation");
        return;
    }
    assert!(trusted_secret_path(&link, &root, 4096, false, "cert").is_err());
}

#[test]
fn fanout_interval_defaults_to_the_ingest_replay_cadence_and_is_bounded() {
    use std::time::Duration;

    // Unset and empty both mean "the default", which is deliberately the same
    // 5s `event-ingest`'s own outbox replay worker uses.
    assert_eq!(
        fanout_interval_value(None).unwrap(),
        Duration::from_secs(5),
        "the default must stay pinned to event-ingest's replay cadence"
    );
    assert_eq!(fanout_interval_value(Some("")).unwrap(), Duration::from_secs(5));
    assert_eq!(fanout_interval_value(Some("1")).unwrap(), Duration::from_secs(1));
    assert_eq!(
        fanout_interval_value(Some("3600")).unwrap(),
        Duration::from_secs(3600)
    );

    // Zero is the one that matters: a zero-interval sleep is a busy loop that
    // would take and release the outbox mutex the accept path shares as fast
    // as the scheduler allows.
    assert!(fanout_interval_value(Some("0")).is_err());
    assert!(fanout_interval_value(Some("3601")).is_err());
    for bad in ["-1", "5s", "five", "1.5", " 5"] {
        assert!(
            fanout_interval_value(Some(bad)).is_err(),
            "{bad:?} must not parse as a fanout interval"
        );
    }
}

#[test]
fn nats_retry_attempts_matches_the_transport_ceiling() {
    assert_eq!(nats_retry_attempts_value(None).unwrap(), 3);
    assert_eq!(nats_retry_attempts_value(Some("")).unwrap(), 3);
    assert_eq!(nats_retry_attempts_value(Some("1")).unwrap(), 1);
    // 8 is `RetryingJetStreamTransport::new`'s own hard ceiling; anything the
    // env accepts past it would be refused later, at first publish, as an
    // opaque INVALID_RETRY_CONFIGURATION rather than at startup.
    assert_eq!(nats_retry_attempts_value(Some("8")).unwrap(), 8);
    assert!(nats_retry_attempts_value(Some("0")).is_err());
    assert!(nats_retry_attempts_value(Some("9")).is_err());
    assert!(nats_retry_attempts_value(Some("three")).is_err());
}

#[test]
fn control_postgres_url_is_this_crate_s_own_variable() {
    assert_eq!(control_postgres_url_value(None, None).unwrap(), None);
    assert_eq!(
        control_postgres_url_value(Some("postgres://apex@db/control"), None).unwrap(),
        Some("postgres://apex@db/control".to_owned())
    );

    // `apex_event_ingest::PostgresOutbox` hardcodes the `apex_event_outbox`
    // table name, so honouring event-ingest's variable here would silently
    // point the control gateway at the ingest gateway's outbox table -- where
    // each service's replay worker would claim and republish the other's rows
    // through its own sinks. Both of these must fail closed.
    assert!(control_postgres_url_value(None, Some("postgres://apex@db/apex")).is_err());
    assert!(
        control_postgres_url_value(
            Some("postgres://apex@db/control"),
            Some("postgres://apex@db/apex")
        )
        .is_err()
    );
}

/// The fanout worker runs as a tokio task, and
/// `AsyncNatsJetStreamClient::connect` bottoms out in `Runtime::block_on`,
/// which **panics** when the calling thread already has a runtime entered.
/// Building the client inline in the worker would therefore look correct,
/// compile, pass every in-process test that never spawns the worker on a real
/// runtime -- and abort on the first tick inside the container.
///
/// This drives the real publisher from inside a real multi-thread runtime,
/// against a broker that does not exist, and asserts the call *returns an
/// error*. A regression that connects on the runtime thread fails this as a
/// panic rather than as an assertion, which is the point.
#[cfg(feature = "test-support")]
#[test]
fn lazy_jetstream_publisher_connects_without_panicking_inside_the_worker_runtime() {
    use apex_event_ingest::{EventPublisher, IngestRequest, NatsTlsConfig};

    use super::fanout::LazyJetStreamPublisher;

    let base = scratch("lazy-publisher");
    for name in ["ca.pem", "client.pem", "client.key"] {
        fs::write(base.join(name), b"-----BEGIN CERTIFICATE-----\nnot-real\n").unwrap();
    }
    let key = base.join("client.key").canonicalize().unwrap();
    if !apex_event_ingest::permissions::private_key_permissions_restricted(&key) {
        // Same reason the symlink case skips: the host's default file ACL is
        // not what this test is about, and `NatsTlsConfig::validated` would
        // refuse the key before any connection is attempted.
        eprintln!("skip lazy publisher case: this host's default key permissions are too broad");
        return;
    }
    let config = NatsTlsConfig {
        // Port 1 on loopback: refused immediately rather than after the 5s
        // connect timeout, so this stays a fast unit test.
        server_url: "tls://127.0.0.1:1".to_owned(),
        ca_file: base.join("ca.pem"),
        client_cert_file: base.join("client.pem"),
        client_key_file: key,
        username_file: None,
        password_file: None,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let outcome = runtime.block_on(async move {
        let mut publisher = LazyJetStreamPublisher::new(config, base.clone(), 3);
        let request = IngestRequest::new(
            "018f0000-0000-7000-8000-000000000000",
            "acme",
            "prod",
            vec![1, 2, 3],
        );
        tokio::spawn(async move { publisher.publish(&request) })
            .await
            .expect("the publish task must not panic")
    });
    // An error, not a success: the row stays pending and the worker retries,
    // which is exactly the degraded-fanout behaviour ADR-0006 requires.
    assert!(
        outcome.is_err(),
        "an unreachable broker must surface as a deferred publish, not a success"
    );
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}
