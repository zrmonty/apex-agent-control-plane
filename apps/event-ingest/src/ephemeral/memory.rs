use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::types::{
    DenyHintKey, EphemeralError, EphemeralStore, FingerprintCounterKey, RateLimitDecision,
    RateLimitKey, validate_deny_key, validate_fingerprint_key, validate_rate_key, window_secs,
};

const MAX_KEYS: usize = 50_000;

#[derive(Debug)]
struct RateBucket {
    window_started: Instant,
    count: u32,
}

#[derive(Debug)]
struct FingerprintBucket {
    window_started: Instant,
    count: u64,
}

#[derive(Debug)]
struct DenyBucket {
    expires_at: Instant,
}

/// Process-local bounded fallback used when Valkey is disabled or unavailable.
#[derive(Debug, Default)]
pub struct InMemoryEphemeralStore {
    rates: HashMap<RateLimitKey, RateBucket>,
    fingerprints: HashMap<FingerprintCounterKey, FingerprintBucket>,
    denies: HashMap<DenyHintKey, DenyBucket>,
}

impl InMemoryEphemeralStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn total_keys(&self) -> usize {
        self.rates.len() + self.fingerprints.len() + self.denies.len()
    }
}

impl EphemeralStore for InMemoryEphemeralStore {
    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        validate_rate_key(key)?;
        if limit == 0 || window_secs(window).is_err() {
            return Err(EphemeralError::invalid_key());
        }
        if !self.rates.contains_key(key) && self.total_keys() >= MAX_KEYS {
            return Err(EphemeralError::capacity());
        }
        let now = Instant::now();
        let bucket = self.rates.entry(key.clone()).or_insert(RateBucket {
            window_started: now,
            count: 0,
        });
        if now.duration_since(bucket.window_started) >= window {
            bucket.window_started = now;
            bucket.count = 0;
        }
        if bucket.count >= limit {
            return Ok(RateLimitDecision {
                allowed: false,
                remaining: 0,
            });
        }
        bucket.count += 1;
        Ok(RateLimitDecision {
            allowed: true,
            remaining: limit.saturating_sub(bucket.count),
        })
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        let _ = window_secs(window)?;
        if !self.fingerprints.contains_key(key) && self.total_keys() >= MAX_KEYS {
            return Err(EphemeralError::capacity());
        }
        let now = Instant::now();
        let bucket = self
            .fingerprints
            .entry(key.clone())
            .or_insert(FingerprintBucket {
                window_started: now,
                count: 0,
            });
        if now.duration_since(bucket.window_started) >= window {
            bucket.window_started = now;
            bucket.count = 0;
        }
        bucket.count = bucket.count.saturating_add(1);
        Ok(bucket.count)
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        Ok(self
            .fingerprints
            .get(key)
            .map(|bucket| bucket.count)
            .unwrap_or(0))
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        validate_deny_key(key)?;
        let secs = window_secs(ttl)?;
        if !self.denies.contains_key(key) && self.total_keys() >= MAX_KEYS {
            return Err(EphemeralError::capacity());
        }
        self.denies.insert(
            key.clone(),
            DenyBucket {
                expires_at: Instant::now() + Duration::from_secs(secs),
            },
        );
        Ok(())
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        validate_deny_key(key)?;
        Ok(self
            .denies
            .get(key)
            .is_some_and(|bucket| Instant::now() < bucket.expires_at))
    }
}
