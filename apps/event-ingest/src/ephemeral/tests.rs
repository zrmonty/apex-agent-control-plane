use super::*;
#[cfg(feature = "valkey")]
use std::collections::HashMap;
use std::time::Duration;

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

#[cfg(feature = "valkey")]
mod valkey_protocol {
    use super::*;
    use crate::ephemeral::types::{
        deny_hint_redis_key, fingerprint_redis_key, rate_limit_redis_key,
    };
    use crate::ephemeral::valkey::{ScriptedValkeyStore, ValkeyCommandSink};

    #[derive(Default)]
    struct MapSink {
        counters: HashMap<String, u64>,
        flags: HashMap<String, bool>,
        ttls: HashMap<String, u64>,
    }

    impl ValkeyCommandSink for MapSink {
        fn incr(&mut self, key: &str) -> Result<u64, EphemeralError> {
            let entry = self.counters.entry(key.to_owned()).or_insert(0);
            *entry += 1;
            Ok(*entry)
        }
        fn expire(&mut self, key: &str, ttl_secs: u64) -> Result<(), EphemeralError> {
            self.ttls.insert(key.to_owned(), ttl_secs);
            Ok(())
        }
        fn get_u64(&mut self, key: &str) -> Result<Option<u64>, EphemeralError> {
            Ok(self.counters.get(key).copied())
        }
        fn set_ex(&mut self, key: &str, ttl_secs: u64) -> Result<(), EphemeralError> {
            self.flags.insert(key.to_owned(), true);
            self.ttls.insert(key.to_owned(), ttl_secs);
            Ok(())
        }
        fn get_flag(&mut self, key: &str) -> Result<bool, EphemeralError> {
            Ok(self.flags.get(key).copied().unwrap_or(false))
        }
    }

    #[test]
    fn scripted_valkey_uses_namespaced_key_shapes() {
        let mut store = ScriptedValkeyStore::new(MapSink::default());
        let key = RateLimitKey {
            namespace: "acme".into(),
            bucket: "ingest".into(),
        };
        store
            .check_rate_limit(&key, 2, Duration::from_secs(10))
            .unwrap();
        let expected = rate_limit_redis_key(&key);
        assert!(expected.starts_with("apex:ingest:rl:"));
        let fp = FingerprintCounterKey {
            namespace: "acme".into(),
            fingerprint_hex: "ab".into(),
        };
        store
            .increment_fingerprint(&fp, Duration::from_secs(5))
            .unwrap();
        assert!(fingerprint_redis_key(&fp).contains(":fp:"));
        let deny = DenyHintKey {
            namespace: "acme".into(),
            identity_fingerprint_hex: "cd".into(),
        };
        store.set_deny_hint(&deny, Duration::from_secs(5)).unwrap();
        assert!(store.is_denied(&deny).unwrap());
        assert!(deny_hint_redis_key(&deny).contains(":deny:"));
    }

    /// `is_scope_identifier` permits `:` inside a workspace or namespace, and
    /// `:` is also the separator between Valkey key components. Distinct
    /// scopes must never collapse onto one key: these keys hold per-tenant
    /// rate-limit counters and deny hints, so a collision lets one tenant
    /// spend another's admission budget or trip another's deny hint.
    #[test]
    fn valkey_keys_cannot_collide_across_scopes_containing_the_separator() {
        assert!(crate::is_scope_identifier("acme:prod"));

        let left = RateLimitKey {
            namespace: "acme:prod".into(),
            bucket: "admission".into(),
        };
        let right = RateLimitKey {
            namespace: "acme".into(),
            bucket: "prod:admission".into(),
        };
        assert_ne!(rate_limit_redis_key(&left), rate_limit_redis_key(&right));

        let left_fp = FingerprintCounterKey {
            namespace: "auth:failures".into(),
            fingerprint_hex: "ab".into(),
        };
        let right_fp = FingerprintCounterKey {
            namespace: "auth".into(),
            fingerprint_hex: "failures:ab".into(),
        };
        assert_ne!(
            fingerprint_redis_key(&left_fp),
            fingerprint_redis_key(&right_fp)
        );

        let left_deny = DenyHintKey {
            namespace: "auth:failures".into(),
            identity_fingerprint_hex: "cd".into(),
        };
        let right_deny = DenyHintKey {
            namespace: "auth".into(),
            identity_fingerprint_hex: "failures:cd".into(),
        };
        assert_ne!(
            deny_hint_redis_key(&left_deny),
            deny_hint_redis_key(&right_deny)
        );

        // Distinct scopes still map to stable, distinct keys under the prefix.
        let other = RateLimitKey {
            namespace: "other".into(),
            bucket: "admission".into(),
        };
        assert_ne!(rate_limit_redis_key(&left), rate_limit_redis_key(&other));
        assert!(rate_limit_redis_key(&other).starts_with("apex:ingest:rl:"));
    }
}
