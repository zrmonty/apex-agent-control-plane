// Startup tests for runtime.

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
    use apex_durability::{EventPublisher, IngestRequest, NatsTlsConfig};

    use super::fanout::LazyJetStreamPublisher;

    let base = scratch("lazy-publisher");
    for name in ["ca.pem", "client.pem", "client.key"] {
        fs::write(base.join(name), b"-----BEGIN CERTIFICATE-----\nnot-real\n").unwrap();
    }
    let key = base.join("client.key").canonicalize().unwrap();
    if !apex_durability::permissions::private_key_permissions_restricted(&key) {
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
