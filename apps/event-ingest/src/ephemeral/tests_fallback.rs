// `FallbackEphemeralStore` behavior: routing around an unavailable primary,
// the accelerator circuit breaker (cooldown, probe, reinstatement), and that
// caller errors are never mistaken for accelerator health problems.

#[test]
fn fallback_uses_memory_when_primary_unavailable() {
    struct Dead;
    impl EphemeralStore for Dead {
        fn check_rate_limit(
            &mut self,
            _key: &RateLimitKey,
            _limit: u32,
            _window: Duration,
        ) -> Result<RateLimitDecision, EphemeralError> {
            Err(EphemeralError::unavailable())
        }
        fn increment_fingerprint(
            &mut self,
            _key: &FingerprintCounterKey,
            _window: Duration,
        ) -> Result<u64, EphemeralError> {
            Err(EphemeralError::unavailable())
        }
        fn fingerprint_count(
            &mut self,
            _key: &FingerprintCounterKey,
        ) -> Result<u64, EphemeralError> {
            Err(EphemeralError::unavailable())
        }
        fn set_deny_hint(
            &mut self,
            _key: &DenyHintKey,
            _ttl: Duration,
        ) -> Result<(), EphemeralError> {
            Err(EphemeralError::unavailable())
        }
        fn is_denied(&mut self, _key: &DenyHintKey) -> Result<bool, EphemeralError> {
            Err(EphemeralError::unavailable())
        }
    }

    let mut store = FallbackEphemeralStore::new(Dead, InMemoryEphemeralStore::new());
    let key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    assert!(
        store
            .check_rate_limit(&key, 1, Duration::from_secs(1))
            .unwrap()
            .allowed
    );
}

/// Counts how often the primary is actually dialled.
struct CountingPrimary {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    healthy: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CountingPrimary {
    fn answer<T>(&mut self, value: T) -> Result<T, EphemeralError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.healthy.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(value)
        } else {
            Err(EphemeralError::unavailable())
        }
    }
}

impl EphemeralStore for CountingPrimary {
    fn check_rate_limit(
        &mut self,
        _key: &RateLimitKey,
        limit: u32,
        _window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        self.answer(RateLimitDecision {
            allowed: true,
            remaining: limit,
        })
    }
    fn increment_fingerprint(
        &mut self,
        _key: &FingerprintCounterKey,
        _window: Duration,
    ) -> Result<u64, EphemeralError> {
        self.answer(1)
    }
    fn fingerprint_count(&mut self, _key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        self.answer(1)
    }
    fn set_deny_hint(&mut self, _key: &DenyHintKey, _ttl: Duration) -> Result<(), EphemeralError> {
        self.answer(())
    }
    fn is_denied(&mut self, _key: &DenyHintKey) -> Result<bool, EphemeralError> {
        self.answer(false)
    }
}

/// An unavailable accelerator must be dialled once, not on every call.
///
/// Redialling per call is not merely wasteful: the redial cost is not bounded
/// by the connect timeout (name resolution is not covered by it), the whole
/// store sits behind one process-wide mutex, and several ephemeral operations
/// run per ingest. Measured against a live gateway with Valkey stopped, one
/// valid ingest took 135 seconds. This is the regression guard for that.
#[test]
fn an_unavailable_primary_is_not_redialled_on_every_call() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let healthy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut store = FallbackEphemeralStore::with_cooldown(
        CountingPrimary {
            calls: calls.clone(),
            healthy: healthy.clone(),
        },
        InMemoryEphemeralStore::new(),
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };

    for _ in 0..50 {
        // Every call must still be served, from the local store.
        store
            .check_rate_limit(&key, 1000, Duration::from_secs(1))
            .expect("the local fallback must answer while the primary is down");
    }

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the dead accelerator was dialled on every call; 50 calls should cost \
         exactly one failed dial, then be served locally until the cool-down \
         expires"
    );
    assert!(
        store.accelerator_sidelined(),
        "the breaker must be open after the primary reported Unavailable"
    );
}

/// The breaker must not be a one-way door: once the accelerator answers again,
/// it has to be used again.
#[test]
fn the_primary_is_retried_after_the_cooldown_and_reinstated_on_success() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let healthy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut store = FallbackEphemeralStore::with_cooldown(
        CountingPrimary {
            calls: calls.clone(),
            healthy: healthy.clone(),
        },
        InMemoryEphemeralStore::new(),
        Duration::from_millis(50),
        Duration::from_millis(50),
    );
    let key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };

    store
        .check_rate_limit(&key, 1000, Duration::from_secs(1))
        .expect("first call");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Inside the cool-down: no further dials.
    store
        .check_rate_limit(&key, 1000, Duration::from_secs(1))
        .expect("second call");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // After the cool-down the accelerator is probed again, and once it answers
    // the breaker closes and it is used normally from then on.
    std::thread::sleep(Duration::from_millis(80));
    healthy.store(true, std::sync::atomic::Ordering::SeqCst);
    store
        .check_rate_limit(&key, 1000, Duration::from_secs(1))
        .expect("probe call");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the accelerator must be probed again once the cool-down expires"
    );
    assert!(
        !store.accelerator_sidelined(),
        "a successful probe must close the breaker"
    );

    store
        .check_rate_limit(&key, 1000, Duration::from_secs(1))
        .expect("post-recovery call");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "a recovered accelerator must be used on every call again"
    );
}

/// A caller error says nothing about the accelerator's health.
#[test]
fn an_invalid_key_neither_trips_the_breaker_nor_falls_back() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let healthy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut store = FallbackEphemeralStore::with_cooldown(
        CountingPrimary {
            calls: calls.clone(),
            healthy: healthy.clone(),
        },
        InMemoryEphemeralStore::new(),
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    // The in-memory primary validates keys; use the real one to produce a
    // genuine InvalidKey rather than a synthetic error.
    let mut real = FallbackEphemeralStore::with_cooldown(
        InMemoryEphemeralStore::new(),
        InMemoryEphemeralStore::new(),
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let bad = RateLimitKey {
        namespace: String::new(),
        bucket: "ingest".into(),
    };
    assert_eq!(
        real.check_rate_limit(&bad, 1, Duration::from_secs(1))
            .unwrap_err()
            .code,
        EphemeralErrorCode::InvalidKey,
        "an invalid key must surface as an error, not be retried locally"
    );
    assert!(
        !real.accelerator_sidelined(),
        "a caller error must not sideline a healthy accelerator"
    );

    // And a healthy primary is never sidelined by normal use.
    let key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    store
        .check_rate_limit(&key, 1000, Duration::from_secs(1))
        .expect("healthy call");
    assert!(!store.accelerator_sidelined());
}

/// A primary whose every operation returns a fixed, injected result --
/// `Ok(())`-shaped success is impossible to express generically here, so
/// each test picks the operation it cares about and ignores the others'
/// return values via the fixed error/pass-through convention below.
struct ScriptedPrimary {
    error: Option<EphemeralError>,
}

impl EphemeralStore for ScriptedPrimary {
    fn check_rate_limit(
        &mut self,
        _key: &RateLimitKey,
        _limit: u32,
        _window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(RateLimitDecision {
                allowed: true,
                remaining: 41,
            }),
        }
    }
    fn increment_fingerprint(
        &mut self,
        _key: &FingerprintCounterKey,
        _window: Duration,
    ) -> Result<u64, EphemeralError> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(41),
        }
    }
    fn fingerprint_count(&mut self, _key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(41),
        }
    }
    fn set_deny_hint(&mut self, _key: &DenyHintKey, _ttl: Duration) -> Result<(), EphemeralError> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
    fn is_denied(&mut self, _key: &DenyHintKey) -> Result<bool, EphemeralError> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(true),
        }
    }
}

#[test]
fn fallback_falls_back_for_every_operation_when_primary_is_unavailable() {
    let mut store = FallbackEphemeralStore::new(
        ScriptedPrimary {
            error: Some(EphemeralError::unavailable()),
        },
        InMemoryEphemeralStore::new(),
    );
    let rate_key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    let fp_key = FingerprintCounterKey {
        namespace: "acme".into(),
        fingerprint_hex: "ab".into(),
    };
    let deny_key = DenyHintKey {
        namespace: "acme".into(),
        identity_fingerprint_hex: "cd".into(),
    };
    // The in-memory fallback starts empty, so a successful, non-41 result
    // proves the primary's Unavailable error was routed around rather than
    // propagated.
    let decision = store
        .check_rate_limit(&rate_key, 5, Duration::from_secs(60))
        .unwrap();
    assert_ne!(decision.remaining, 41);
    assert_eq!(
        store
            .increment_fingerprint(&fp_key, Duration::from_secs(60))
            .unwrap(),
        1
    );
    assert_eq!(store.fingerprint_count(&fp_key).unwrap(), 1);
    assert!(!store.is_denied(&deny_key).unwrap());
    store
        .set_deny_hint(&deny_key, Duration::from_secs(30))
        .unwrap();
    assert!(store.is_denied(&deny_key).unwrap());
}

#[test]
fn fallback_does_not_mask_non_unavailable_primary_errors() {
    let mut store = FallbackEphemeralStore::new(
        ScriptedPrimary {
            error: Some(EphemeralError::invalid_key()),
        },
        InMemoryEphemeralStore::new(),
    );
    let rate_key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    let fp_key = FingerprintCounterKey {
        namespace: "acme".into(),
        fingerprint_hex: "ab".into(),
    };
    let deny_key = DenyHintKey {
        namespace: "acme".into(),
        identity_fingerprint_hex: "cd".into(),
    };
    assert_eq!(
        store
            .check_rate_limit(&rate_key, 5, Duration::from_secs(60))
            .unwrap_err()
            .code,
        EphemeralErrorCode::InvalidKey
    );
    assert_eq!(
        store
            .increment_fingerprint(&fp_key, Duration::from_secs(60))
            .unwrap_err()
            .code,
        EphemeralErrorCode::InvalidKey
    );
    assert_eq!(
        store.fingerprint_count(&fp_key).unwrap_err().code,
        EphemeralErrorCode::InvalidKey
    );
    assert_eq!(
        store
            .set_deny_hint(&deny_key, Duration::from_secs(30))
            .unwrap_err()
            .code,
        EphemeralErrorCode::InvalidKey
    );
    assert_eq!(
        store.is_denied(&deny_key).unwrap_err().code,
        EphemeralErrorCode::InvalidKey
    );
}

#[test]
fn fallback_uses_the_primary_result_when_it_succeeds() {
    let mut store =
        FallbackEphemeralStore::new(ScriptedPrimary { error: None }, InMemoryEphemeralStore::new());
    let rate_key = RateLimitKey {
        namespace: "acme".into(),
        bucket: "ingest".into(),
    };
    let fp_key = FingerprintCounterKey {
        namespace: "acme".into(),
        fingerprint_hex: "ab".into(),
    };
    let deny_key = DenyHintKey {
        namespace: "acme".into(),
        identity_fingerprint_hex: "cd".into(),
    };
    assert_eq!(
        store
            .check_rate_limit(&rate_key, 5, Duration::from_secs(60))
            .unwrap()
            .remaining,
        41
    );
    assert_eq!(
        store
            .increment_fingerprint(&fp_key, Duration::from_secs(60))
            .unwrap(),
        41
    );
    assert_eq!(store.fingerprint_count(&fp_key).unwrap(), 41);
    store
        .set_deny_hint(&deny_key, Duration::from_secs(30))
        .unwrap();
    assert!(store.is_denied(&deny_key).unwrap());
    let _ = store.primary();
    let _ = store.fallback();
}
