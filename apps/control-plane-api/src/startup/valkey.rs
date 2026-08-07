//! Lazily-connected wrapper around `event-ingest`'s `ValkeyEphemeralStore`.
//!
//! `ValkeyEphemeralStore::connect` dials during construction, which is what
//! `event-ingest` wants: its startup refuses to come up without the
//! accelerator it was told to use. The out-of-band control gateway cannot make
//! that trade. An explicitly non-authoritative rate-limit accelerator must
//! never be a startup dependency of the one channel ADR-0006 requires to stay
//! reachable when everything else is degraded -- the same argument that made
//! the JetStream publisher connect lazily rather than during `run()`.
//!
//! So this defers the dial to first use and re-dials after a failure, which
//! also means a Valkey that happened to be down when this process booted is
//! picked up without a restart.
//!
//! # This does not reintroduce the 135-second stall
//!
//! `ephemeral/fallback.rs` records the incident: without a circuit breaker,
//! every ephemeral call re-dialled a dead accelerator, each dial cost a TCP
//! connect timeout *plus* name resolution (~3.85s against Docker's embedded
//! resolver, measured), the store sits behind one process-wide mutex, and a
//! single live ingest took 135 seconds. This type is deliberately the
//! **primary** inside a [`apex_event_ingest::FallbackEphemeralStore`], never
//! used bare, so a failed dial trips that breaker and the next calls skip it
//! entirely and serve from the local store, retrying on a 1s -> 30s backoff.
//! One slow probe per cool-down, not one per request.
//!
//! `ControlGatewayService::admit` additionally runs the whole store call on a
//! blocking thread, so even that one probe cannot stall the tonic worker that
//! is holding other requests.

use apex_event_ingest::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FingerprintCounterKey,
    RateLimitDecision, RateLimitKey, ValkeyConfig, ValkeyEphemeralStore,
};
use std::time::Duration;

pub(crate) struct LazyValkeyStore {
    config: ValkeyConfig,
    inner: Option<ValkeyEphemeralStore>,
}

impl LazyValkeyStore {
    pub(crate) fn new(config: ValkeyConfig) -> Self {
        Self {
            config,
            inner: None,
        }
    }

    fn run<T>(
        &mut self,
        operation: impl FnOnce(&mut ValkeyEphemeralStore) -> Result<T, EphemeralError>,
    ) -> Result<T, EphemeralError> {
        if self.inner.is_none() {
            self.inner = Some(ValkeyEphemeralStore::connect(&self.config)?);
        }
        let store = self
            .inner
            .as_mut()
            .ok_or_else(EphemeralError::unavailable)?;
        let result = operation(store);
        if matches!(&result, Err(error) if error.code == EphemeralErrorCode::Unavailable) {
            // `ValkeyEphemeralStore` already rebuilds its own connection after
            // a command error, precisely because a timed-out command can leave
            // an unread reply on the wire and desync the protocol. If that
            // rebuild also failed, the held connection is unusable and reusing
            // it would produce a second failure on the next call. Drop it so
            // the next call reconnects -- which the breaker above will not
            // even reach until its cool-down expires.
            self.inner = None;
        }
        result
    }
}

impl EphemeralStore for LazyValkeyStore {
    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        self.run(|store| store.check_rate_limit(key, limit, window))
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        self.run(|store| store.increment_fingerprint(key, window))
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        self.run(|store| store.fingerprint_count(key))
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        self.run(|store| store.set_deny_hint(key, ttl))
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        self.run(|store| store.is_denied(key))
    }
}
