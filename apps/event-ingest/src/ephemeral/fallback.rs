use std::time::{Duration, Instant};

use super::types::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FingerprintCounterKey,
    RateLimitDecision, RateLimitKey,
};

/// First cool-down after the accelerator is found unavailable.
const INITIAL_COOLDOWN: Duration = Duration::from_secs(1);
/// Ceiling for the cool-down. Long enough that a sustained outage costs at most
/// one probe every 30s, short enough that recovery is picked up promptly.
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

/// Prefer a remote accelerator; on `Unavailable`, use the local fallback.
///
/// Protected endpoints must still fail closed when **both** backends fail.
/// Successful local fallback decisions never grant more than the configured limit.
///
/// # Why there is a circuit breaker here
///
/// Without one, every call re-dialled a dead accelerator, and the cost of a
/// redial is not bounded by the connect timeout. `ValkeyEphemeralStore` sets a
/// 3s `get_connection_with_timeout`, but that bounds the TCP connect, not name
/// resolution: against Docker's embedded resolver an unresolvable service name
/// takes ~3.85s per lookup, measured. Several ephemeral operations run per
/// ingest (a rate-limit check, a fingerprint increment, a deny-hint read), each
/// one re-dialling, and the whole store sits behind a single process-wide
/// mutex that `admit_request` holds. Every admission in the process therefore
/// queues behind those stalls.
///
/// Measured against a live gateway with the accelerator stopped: one valid
/// ingest took **135 seconds**, against well under a second healthy. Nothing
/// was admitted that should not have been and no acknowledgement was untrue --
/// this is availability, not integrity -- but an *optional, explicitly
/// non-authoritative* accelerator going away took the ingest path down with it,
/// which is the opposite of what the fallback exists to provide.
///
/// The breaker restores the intended behaviour: once the primary is known bad,
/// skip it entirely and serve from the local store, retrying on a backoff. A
/// sustained outage costs one slow probe per cool-down instead of one per call.
pub struct FallbackEphemeralStore<P, F> {
    primary: P,
    fallback: F,
    breaker: Breaker,
}

/// Tracks whether the primary is currently believed dead, and for how long to
/// keep believing it.
#[derive(Debug)]
struct Breaker {
    open_until: Option<Instant>,
    cooldown: Duration,
    initial_cooldown: Duration,
    max_cooldown: Duration,
}

impl Breaker {
    fn new(initial_cooldown: Duration, max_cooldown: Duration) -> Self {
        Self {
            open_until: None,
            cooldown: initial_cooldown,
            initial_cooldown,
            max_cooldown,
        }
    }

    fn is_open(&self) -> bool {
        self.open_until.is_some_and(|until| Instant::now() < until)
    }

    /// Primary failed: stay away from it for the current cool-down, then double
    /// the cool-down so a sustained outage converges on the ceiling rather than
    /// probing at a fixed high rate.
    fn trip(&mut self) {
        self.open_until = Some(Instant::now() + self.cooldown);
        self.cooldown = self.cooldown.saturating_mul(2).min(self.max_cooldown);
    }

    /// Primary answered: close the breaker and forget the backoff, so a brief
    /// blip does not leave the accelerator sidelined for 30s afterwards.
    fn reset(&mut self) {
        if self.open_until.is_some() || self.cooldown != self.initial_cooldown {
            self.open_until = None;
            self.cooldown = self.initial_cooldown;
        }
    }
}

impl<P, F> FallbackEphemeralStore<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self::with_cooldown(primary, fallback, INITIAL_COOLDOWN, MAX_COOLDOWN)
    }

    /// Explicit cool-down bounds. Exists so tests can exercise the breaker
    /// without sleeping for seconds.
    pub fn with_cooldown(
        primary: P,
        fallback: F,
        initial_cooldown: Duration,
        max_cooldown: Duration,
    ) -> Self {
        Self {
            primary,
            fallback,
            breaker: Breaker::new(initial_cooldown, max_cooldown),
        }
    }

    pub fn primary(&self) -> &P {
        &self.primary
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }

    /// True while the primary is being skipped.
    pub fn accelerator_sidelined(&self) -> bool {
        self.breaker.is_open()
    }
}

impl<P, F> FallbackEphemeralStore<P, F> {
    /// Runs `primary`, falling back to `fallback` on `Unavailable`, and skips
    /// the primary entirely while the breaker is open.
    ///
    /// Only `Unavailable` trips the breaker. An `InvalidKey` is a caller
    /// problem that says nothing about the accelerator's health and must not
    /// sideline it, and it must still surface as an error rather than being
    /// quietly retried against the local store.
    fn route<T>(
        &mut self,
        primary: impl FnOnce(&mut P) -> Result<T, EphemeralError>,
        fallback: impl FnOnce(&mut F) -> Result<T, EphemeralError>,
    ) -> Result<T, EphemeralError> {
        if self.breaker.is_open() {
            return fallback(&mut self.fallback);
        }
        match primary(&mut self.primary) {
            Ok(value) => {
                self.breaker.reset();
                Ok(value)
            }
            Err(error) if error.code == EphemeralErrorCode::Unavailable => {
                self.breaker.trip();
                fallback(&mut self.fallback)
            }
            Err(error) => Err(error),
        }
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
        self.route(
            |primary| primary.check_rate_limit(key, limit, window),
            |fallback| fallback.check_rate_limit(key, limit, window),
        )
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        self.route(
            |primary| primary.increment_fingerprint(key, window),
            |fallback| fallback.increment_fingerprint(key, window),
        )
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        self.route(
            |primary| primary.fingerprint_count(key),
            |fallback| fallback.fingerprint_count(key),
        )
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        self.route(
            |primary| primary.set_deny_hint(key, ttl),
            |fallback| fallback.set_deny_hint(key, ttl),
        )
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        self.route(
            |primary| primary.is_denied(key),
            |fallback| fallback.is_denied(key),
        )
    }
}
