// Valkey wire-protocol key-shape tests: namespaced key construction and
// collision-safety across scopes that themselves contain the `:` separator.

#[cfg(feature = "valkey")]
mod valkey_protocol {
    use super::*;
    use crate::ephemeral::types::{
        deny_hint_redis_key, fingerprint_redis_key, rate_limit_redis_key,
    };
    use crate::ephemeral::valkey::{ScriptedValkeyStore, ValkeyCommandSink};
    use std::collections::HashMap;

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
