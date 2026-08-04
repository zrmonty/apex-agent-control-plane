use std::time::Duration;

use super::types::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FingerprintCounterKey,
    RateLimitDecision, RateLimitKey,
};

/// Prefer a remote accelerator; on `Unavailable`, use the local fallback.
///
/// Protected endpoints must still fail closed when **both** backends fail.
/// Successful local fallback decisions never grant more than the configured limit.
pub struct FallbackEphemeralStore<P, F> {
    primary: P,
    fallback: F,
}

impl<P, F> FallbackEphemeralStore<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }

    pub fn primary(&self) -> &P {
        &self.primary
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }
}

impl<P, F> EphemeralStore for FallbackEphemeralStore<P, F>
where
    P: EphemeralStore,
    F: EphemeralStore,
{
    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        match self.primary.check_rate_limit(key, limit, window) {
            Ok(decision) => Ok(decision),
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.fallback.check_rate_limit(key, limit, window)
            }
            Err(error) => Err(error),
        }
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        match self.primary.increment_fingerprint(key, window) {
            Ok(count) => Ok(count),
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.fallback.increment_fingerprint(key, window)
            }
            Err(error) => Err(error),
        }
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        match self.primary.fingerprint_count(key) {
            Ok(count) => Ok(count),
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.fallback.fingerprint_count(key)
            }
            Err(error) => Err(error),
        }
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        match self.primary.set_deny_hint(key, ttl) {
            Ok(()) => Ok(()),
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.fallback.set_deny_hint(key, ttl)
            }
            Err(error) => Err(error),
        }
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        match self.primary.is_denied(key) {
            Ok(denied) => Ok(denied),
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.fallback.is_denied(key)
            }
            Err(error) => Err(error),
        }
    }
}
