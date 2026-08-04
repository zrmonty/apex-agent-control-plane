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
}
