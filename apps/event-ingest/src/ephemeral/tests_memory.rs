// `InMemoryEphemeralStore` behavior: rate limiting, fingerprint counters,
// deny hints, and key validation, in isolation from the fallback/breaker and
// Valkey-protocol concerns covered by the sibling `tests_*` files.

#[test]
fn rate_limit_admits_until_exhausted_then_denies() {
    let mut store = InMemoryEphemeralStore::new();
    let key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    let window = Duration::from_secs(60);
    assert!(store.check_rate_limit(&key, 2, window).unwrap().allowed);
    let second = store.check_rate_limit(&key, 2, window).unwrap();
    assert!(second.allowed);
    assert_eq!(second.remaining, 0);
    assert!(!store.check_rate_limit(&key, 2, window).unwrap().allowed);
}

#[test]
fn fingerprint_and_deny_hints_are_content_free() {
    let mut store = InMemoryEphemeralStore::new();
    let fp = FingerprintCounterKey {
        namespace: "acme".into(),
        fingerprint_hex: "aabb".into(),
    };
    assert_eq!(
        store
            .increment_fingerprint(&fp, Duration::from_secs(60))
            .unwrap(),
        1
    );
    assert_eq!(store.fingerprint_count(&fp).unwrap(), 1);
    let deny = DenyHintKey {
        namespace: "acme".into(),
        identity_fingerprint_hex: "ccdd".into(),
    };
    assert!(!store.is_denied(&deny).unwrap());
    store.set_deny_hint(&deny, Duration::from_secs(30)).unwrap();
    assert!(store.is_denied(&deny).unwrap());
}

#[test]
fn invalid_keys_fail_closed() {
    let mut store = InMemoryEphemeralStore::new();
    assert_eq!(
        store
            .check_rate_limit(
                &RateLimitKey {
                    namespace: "bad ns".into(),
                    bucket: "ingest".into(),
                },
                1,
                Duration::from_secs(1)
            )
            .unwrap_err()
            .code,
        EphemeralErrorCode::InvalidKey
    );
}
