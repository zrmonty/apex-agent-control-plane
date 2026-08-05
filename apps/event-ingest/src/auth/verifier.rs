use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tonic::transport::server::TlsConnectInfo;

use crate::{
    Caller, DenyHintKey, EphemeralStore, FingerprintCounterKey, GatewayError, GatewayErrorCode,
};

/// Stable identity derived from the authenticated TLS peer certificate.
///
/// The gateway deliberately exposes only a SHA-256 certificate fingerprint to
/// authentication code. It does not log or retain the certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    pub certificate_sha256: [u8; 32],
}

impl PeerIdentity {
    pub(crate) fn from_request<T>(request: &tonic::Request<T>) -> Option<Self> {
        let certs = request
            .extensions()
            .get::<TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()?
            .peer_certs()?;
        let leaf = certs.first()?;
        Some(Self {
            certificate_sha256: Sha256::digest(leaf.as_ref()).into(),
        })
    }
}

/// Verifies transport credentials and returns an authorized caller scope.
pub trait CallerVerifier: Send + Sync + 'static {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError>;

    fn verify_with_peer(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        _peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        self.verify(metadata)
    }
}

/// Deployment-provided token validation and scope mapping.
///
/// Implementations must return a caller created by
/// [`Caller::authenticated_for_agent`]. The gateway rejects anonymous or
/// unbound callers before admission, so a resolver cannot silently widen a
/// credential into arbitrary agent identities. Strict TLS deployments must
/// also override `resolve_with_peer` and bind the credential to the supplied
/// peer certificate fingerprint; the default implementation fails closed when
/// a peer identity is present.
pub trait BearerTokenResolver: Send + Sync + 'static {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError>;

    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        if peer.is_some() {
            // A resolver that has not explicitly implemented certificate
            // binding must not be usable by the strict TLS path.
            return Err(GatewayError::invalid_authorization());
        }
        self.resolve(token)
    }
}

pub struct BearerTokenVerifier<R: BearerTokenResolver> {
    resolver: Arc<R>,
    buckets: Arc<Mutex<HashMap<RateKey, RateBucket>>>,
    require_peer_identity: bool,
    /// Optional non-authoritative accelerator (Valkey or in-memory fallback).
    /// The process-local `buckets` above remain authoritative when this is
    /// unset or unavailable; this only closes the gap where N replicas each
    /// grant an identity its own full `AUTH_FAILURES_PER_SECOND` budget,
    /// multiplying the effective credential-stuffing budget by N.
    ephemeral: Option<Arc<Mutex<Box<dyn EphemeralStore>>>>,
}

const AUTH_FAILURES_PER_SECOND: u32 = 60;
const AUTH_IN_FLIGHT_PER_IDENTITY: u32 = 32;
const MAX_AUTH_IDENTITIES: usize = 4096;
const AUTH_BUCKET_RETENTION: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct RateBucket {
    window_started: Instant,
    failures: u32,
    // Retained for observability; successful authentication is not rejected
    // by this bucket. Post-auth admission limits protect resolver and sink
    // capacity separately.
    successes: u32,
    in_flight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RateKey {
    token: [u8; 32],
    peer: [u8; 32],
}

impl<R: BearerTokenResolver> BearerTokenVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self::with_peer_requirement(resolver, false)
    }

    /// Constructs a verifier that fails closed unless the TLS server exposes a
    /// peer certificate. The runnable gateway uses this mode; `new` remains a
    /// transport-neutral seam for unit tests and non-TLS embedding adapters.
    pub fn new_strict(resolver: R) -> Self {
        Self::with_peer_requirement(resolver, true)
    }

    fn with_peer_requirement(resolver: R, require_peer_identity: bool) -> Self {
        Self {
            resolver: Arc::new(resolver),
            buckets: Arc::new(Mutex::new(HashMap::new())),
            require_peer_identity,
            ephemeral: None,
        }
    }

    /// Attach a shared ephemeral store so the failed-auth budget is enforced
    /// cluster-wide, not per replica. Failures do not fail open: the
    /// process-local bucket above remains the authoritative ceiling.
    pub fn with_ephemeral_store(mut self, store: Arc<Mutex<Box<dyn EphemeralStore>>>) -> Self {
        self.ephemeral = Some(store);
        self
    }
}

impl<R: BearerTokenResolver> BearerTokenVerifier<R> {
    fn admit_attempt(&self, key: RateKey) -> Result<(), GatewayError> {
        if self.distributed_deny_hint_active(key) {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
        let mut buckets = self.buckets.lock().map_err(|_| GatewayError::internal())?;
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            bucket.in_flight > 0 || bucket.window_started.elapsed() < AUTH_BUCKET_RETENTION
        });
        if !buckets.contains_key(&key) && buckets.len() >= MAX_AUTH_IDENTITIES {
            let eviction = buckets
                .iter()
                .filter(|(_, bucket)| bucket.in_flight == 0)
                .min_by_key(|(_, bucket)| bucket.window_started)
                .map(|(key, _)| *key);
            if let Some(eviction) = eviction {
                buckets.remove(&eviction);
            } else {
                // Every slot is actively resolving. Refuse bounded overload,
                // rather than allocating an unbounded attacker-controlled map.
                return Err(GatewayError::new(GatewayErrorCode::RateLimited));
            }
        }
        let bucket = buckets.entry(key).or_insert(RateBucket {
            window_started: now,
            failures: 0,
            successes: 0,
            in_flight: 0,
        });
        if bucket.window_started.elapsed() >= Duration::from_secs(1) {
            *bucket = RateBucket {
                window_started: now,
                failures: 0,
                successes: 0,
                in_flight: 0,
            };
        }
        if bucket.failures >= AUTH_FAILURES_PER_SECOND
            || bucket.in_flight >= AUTH_IN_FLIGHT_PER_IDENTITY
        {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
        bucket.in_flight += 1;
        Ok(())
    }

    fn finish_attempt(&self, key: RateKey, succeeded: bool) {
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let Some(bucket) = buckets.get_mut(&key) else {
            return;
        };
        bucket.in_flight = bucket.in_flight.saturating_sub(1);
        if succeeded {
            bucket.successes = bucket.successes.saturating_add(1);
        } else {
            bucket.failures = bucket.failures.saturating_add(1);
        }
        drop(buckets);
        if !succeeded {
            self.record_distributed_failure(key);
        }
    }

    /// Increments a cluster-wide failure counter for this identity and, once
    /// the fleet-wide budget is exceeded, sets a short-lived shared deny hint
    /// so every replica short-circuits the identity immediately instead of
    /// each independently granting it a fresh local budget. Best-effort: any
    /// ephemeral-store error is swallowed, leaving the local bucket as the
    /// only ceiling for this attempt.
    fn record_distributed_failure(&self, key: RateKey) {
        let Some(store) = &self.ephemeral else {
            return;
        };
        let Ok(mut guard) = store.lock() else {
            return;
        };
        let namespace = "auth-failures";
        let fingerprint_hex = identity_fingerprint_hex(key);
        let fingerprint = FingerprintCounterKey {
            namespace: namespace.to_owned(),
            fingerprint_hex: fingerprint_hex.clone(),
        };
        let Ok(count) = guard.increment_fingerprint(&fingerprint, Duration::from_secs(1)) else {
            return;
        };
        if count > u64::from(AUTH_FAILURES_PER_SECOND) {
            let deny = DenyHintKey {
                namespace: namespace.to_owned(),
                identity_fingerprint_hex: fingerprint_hex,
            };
            let _ = guard.set_deny_hint(&deny, Duration::from_secs(1));
        }
    }

    /// Cheap cluster-wide short-circuit checked before any local bucket or
    /// resolver work: if another replica already tripped this identity's
    /// distributed deny hint, reject immediately rather than each replica
    /// re-discovering the same overload independently.
    fn distributed_deny_hint_active(&self, key: RateKey) -> bool {
        let Some(store) = &self.ephemeral else {
            return false;
        };
        let Ok(mut guard) = store.lock() else {
            return false;
        };
        let deny = DenyHintKey {
            namespace: "auth-failures".to_owned(),
            identity_fingerprint_hex: identity_fingerprint_hex(key),
        };
        guard.is_denied(&deny).unwrap_or(false)
    }

    fn record_malformed_attempt(&self, peer: Option<&PeerIdentity>) -> Result<(), GatewayError> {
        let key = Self::malformed_key(peer);
        if self.distributed_deny_hint_active(key) {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
        let mut buckets = self.buckets.lock().map_err(|_| GatewayError::internal())?;
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            bucket.in_flight > 0 || bucket.window_started.elapsed() < AUTH_BUCKET_RETENTION
        });
        if !buckets.contains_key(&key) && buckets.len() >= MAX_AUTH_IDENTITIES {
            let eviction = buckets
                .iter()
                .filter(|(_, bucket)| bucket.in_flight == 0)
                .min_by_key(|(_, bucket)| bucket.window_started)
                .map(|(key, _)| *key);
            if let Some(eviction) = eviction {
                buckets.remove(&eviction);
            } else {
                return Err(GatewayError::new(GatewayErrorCode::RateLimited));
            }
        }
        let bucket = buckets.entry(key).or_insert(RateBucket {
            window_started: now,
            failures: 0,
            successes: 0,
            in_flight: 0,
        });
        if bucket.window_started.elapsed() >= Duration::from_secs(1) {
            bucket.window_started = now;
            bucket.failures = 0;
            bucket.successes = 0;
        }
        if bucket.failures >= AUTH_FAILURES_PER_SECOND {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
        bucket.failures += 1;
        drop(buckets);
        self.record_distributed_failure(key);
        Ok(())
    }

    fn token_key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn malformed_key(peer: Option<&PeerIdentity>) -> RateKey {
        RateKey {
            token: [0; 32],
            peer: peer.map_or([0; 32], |value| value.certificate_sha256),
        }
    }
}

/// Collapses a token+peer rate key into a single opaque 32-byte fingerprint,
/// hex-encoded to fit the ephemeral store's `is_scope_identifier`-validated
/// fingerprint key shape (raw token/peer hashes concatenated are 64 bytes,
/// over the store's 64-*hex-character* limit).
fn identity_fingerprint_hex(key: RateKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.token);
    hasher.update(key.peer);
    let digest: [u8; 32] = hasher.finalize().into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl<R: BearerTokenResolver> CallerVerifier for BearerTokenVerifier<R> {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        self.verify_with_peer(metadata, None)
    }

    fn verify_with_peer(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        if self.require_peer_identity && peer.is_none() {
            self.record_malformed_attempt(peer)?;
            return Err(GatewayError::unauthenticated());
        }
        let mut values = metadata.get_all("authorization").iter();
        let value = match values.next() {
            Some(value) => value,
            None => {
                self.record_malformed_attempt(peer)?;
                return Err(GatewayError::unauthenticated());
            }
        };
        if values.next().is_some() {
            self.record_malformed_attempt(peer)?;
            return Err(GatewayError::invalid_authorization());
        }
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => {
                self.record_malformed_attempt(peer)?;
                return Err(GatewayError::invalid_authorization());
            }
        };
        let (scheme, token) = match value.split_once(' ') {
            Some(parts) => parts,
            None => {
                self.record_malformed_attempt(peer)?;
                return Err(GatewayError::invalid_authorization());
            }
        };
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            self.record_malformed_attempt(peer)?;
            return Err(GatewayError::invalid_authorization());
        }
        let key = RateKey {
            token: Self::token_key(token),
            peer: peer.map_or([0; 32], |value| value.certificate_sha256),
        };
        self.admit_attempt(key)?;
        // The bucket guard is released before resolver work. A slow or
        // blocking deployment resolver cannot serialize every authentication
        // attempt in the process.
        let result = self.resolver.resolve_with_peer(token, peer);
        self.finish_attempt(key, result.is_ok());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::{MetadataMap, MetadataValue};

    struct RejectingResolver;

    impl BearerTokenResolver for RejectingResolver {
        fn resolve(&self, _token: &str) -> Result<Caller, GatewayError> {
            Err(GatewayError::unauthenticated())
        }
    }

    fn metadata(value: &[u8]) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            MetadataValue::try_from(std::str::from_utf8(value).unwrap()).unwrap(),
        );
        metadata
    }

    #[test]
    fn distributed_deny_hint_is_shared_across_verifier_instances() {
        use crate::{EphemeralStore, InMemoryEphemeralStore};

        let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
            Arc::new(Mutex::new(Box::new(InMemoryEphemeralStore::new())));
        let replica_a =
            BearerTokenVerifier::new(RejectingResolver).with_ephemeral_store(store.clone());
        let replica_b =
            BearerTokenVerifier::new(RejectingResolver).with_ephemeral_store(store.clone());
        let bad = metadata(b"Bearer shared-attacker");

        // Replica A alone can only push the shared distributed counter to
        // AUTH_FAILURES_PER_SECOND before its own *local* bucket starts
        // denying first (identical per-second limit) -- a single replica can
        // never prove the distributed path this way. Spend replica A's full
        // local budget, then a couple of replica B's, so the two replicas'
        // *local-independent* buckets combined push the one shared counter
        // past the threshold.
        for _ in 0..AUTH_FAILURES_PER_SECOND {
            let _ = replica_a.verify(&bad);
        }
        for _ in 0..2 {
            let _ = replica_b.verify(&bad);
        }

        // A brand new replica C has never seen this identity locally at all,
        // but the shared ephemeral store's deny hint must still short-circuit
        // it immediately -- this is the whole point of wiring auth failures
        // through the shared store: N replicas must not each grant their own
        // full failure budget.
        let replica_c = BearerTokenVerifier::new(RejectingResolver).with_ephemeral_store(store);
        assert_eq!(
            replica_c.verify(&bad).unwrap_err().code,
            GatewayErrorCode::RateLimited
        );
    }

    #[test]
    fn ephemeral_store_errors_do_not_block_authentication() {
        use crate::{
            DenyHintKey, EphemeralError, EphemeralStore, FingerprintCounterKey, RateLimitDecision,
            RateLimitKey,
        };

        struct AlwaysUnavailable;
        impl EphemeralStore for AlwaysUnavailable {
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

        let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
            Arc::new(Mutex::new(Box::new(AlwaysUnavailable)));
        let verifier = BearerTokenVerifier::new(AcceptingResolver).with_ephemeral_store(store);
        // A broken ephemeral store must never prevent a legitimate call from
        // succeeding on the local-authoritative path.
        assert!(
            verifier
                .verify(&metadata(b"Bearer valid-token"))
                .unwrap()
                .is_authenticated()
        );
    }

    #[test]
    fn failed_auth_budget_is_scoped_to_the_token_fingerprint() {
        let verifier = BearerTokenVerifier::new(RejectingResolver);
        let first = metadata(b"Bearer attacker-one");
        for _ in 0..AUTH_FAILURES_PER_SECOND {
            assert_eq!(
                verifier.verify(&first).unwrap_err().code,
                GatewayErrorCode::Unauthenticated
            );
        }
        assert_eq!(
            verifier.verify(&first).unwrap_err().code,
            GatewayErrorCode::RateLimited
        );
        assert_eq!(
            verifier
                .verify(&metadata(b"Bearer attacker-two"))
                .unwrap_err()
                .code,
            GatewayErrorCode::Unauthenticated
        );
    }

    #[test]
    fn stale_auth_identities_are_evicted_before_valid_new_identity_is_rejected() {
        let verifier = BearerTokenVerifier::new(RejectingResolver);
        {
            let mut buckets = verifier.buckets.lock().expect("test bucket lock");
            for index in 0..MAX_AUTH_IDENTITIES {
                let mut token = [0u8; 32];
                token[..8].copy_from_slice(&(index as u64).to_le_bytes());
                buckets.insert(
                    RateKey {
                        token,
                        peer: [0; 32],
                    },
                    RateBucket {
                        window_started: Instant::now(),
                        failures: 1,
                        successes: 0,
                        in_flight: 0,
                    },
                );
            }
        }
        let key = RateKey {
            token: [0xff; 32],
            peer: [1; 32],
        };
        assert!(verifier.admit_attempt(key).is_ok());
        assert_eq!(
            verifier.buckets.lock().expect("test bucket lock").len(),
            MAX_AUTH_IDENTITIES
        );
    }

    #[test]
    fn strict_verifier_requires_peer_certificate_and_isolates_peer_budgets() {
        struct PeerTestResolver;
        impl BearerTokenResolver for PeerTestResolver {
            fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
                if token == "valid-token" {
                    Ok(Caller::authenticated("spiffe://apex/test", ["acme/prod"]))
                } else {
                    Err(GatewayError::unauthenticated())
                }
            }

            fn resolve_with_peer(
                &self,
                token: &str,
                peer: Option<&PeerIdentity>,
            ) -> Result<Caller, GatewayError> {
                peer.ok_or_else(GatewayError::unauthenticated)?;
                self.resolve(token)
            }
        }

        let verifier = BearerTokenVerifier::new_strict(PeerTestResolver);
        let request = metadata(b"Bearer valid-token");
        assert_eq!(
            verifier.verify(&request).unwrap_err().code,
            GatewayErrorCode::Unauthenticated
        );

        let first_peer = PeerIdentity {
            certificate_sha256: [1; 32],
        };
        let second_peer = PeerIdentity {
            certificate_sha256: [2; 32],
        };
        assert!(
            verifier
                .verify_with_peer(&request, Some(&first_peer))
                .is_ok()
        );
        for _ in 0..AUTH_FAILURES_PER_SECOND {
            let _ = verifier.verify_with_peer(&metadata(b"Bearer bad-token"), Some(&first_peer));
        }
        assert_eq!(
            verifier
                .verify_with_peer(&metadata(b"Bearer bad-token"), Some(&first_peer))
                .unwrap_err()
                .code,
            GatewayErrorCode::RateLimited
        );
        assert_eq!(
            verifier
                .verify_with_peer(&metadata(b"Bearer bad-token"), Some(&second_peer))
                .unwrap_err()
                .code,
            GatewayErrorCode::Unauthenticated
        );
    }

    struct AcceptingResolver;

    impl BearerTokenResolver for AcceptingResolver {
        fn resolve(&self, _token: &str) -> Result<Caller, GatewayError> {
            Ok(Caller::authenticated("spiffe://apex/test", ["acme/prod"]))
        }
    }

    #[test]
    fn malformed_authorization_headers_fail_closed_and_budget_malformed_attempts() {
        let verifier = BearerTokenVerifier::new(AcceptingResolver);
        let empty = MetadataMap::new();
        assert_eq!(
            verifier.verify(&empty).unwrap_err().code,
            GatewayErrorCode::Unauthenticated
        );

        let mut duplicate = MetadataMap::new();
        duplicate.append(
            "authorization",
            MetadataValue::try_from("Bearer a").unwrap(),
        );
        duplicate.append(
            "authorization",
            MetadataValue::try_from("Bearer b").unwrap(),
        );
        assert_eq!(
            verifier.verify(&duplicate).unwrap_err().code,
            GatewayErrorCode::InvalidAuthorization
        );

        let mut no_space = MetadataMap::new();
        no_space.insert(
            "authorization",
            MetadataValue::try_from("BearerTokenWithoutSpace").unwrap(),
        );
        assert_eq!(
            verifier.verify(&no_space).unwrap_err().code,
            GatewayErrorCode::InvalidAuthorization
        );

        assert!(
            verifier
                .verify(&metadata(b"Bearer valid-token"))
                .unwrap()
                .is_authenticated()
        );

        // Malformed-attempt budget rate-limits after repeated failures.
        for _ in 0..AUTH_FAILURES_PER_SECOND {
            let _ = verifier.verify(&empty);
        }
        assert_eq!(
            verifier.verify(&empty).unwrap_err().code,
            GatewayErrorCode::RateLimited
        );
    }

    #[test]
    fn authorization_parser_rejects_whitespace_controls_and_scheme_ambiguity() {
        let verifier = BearerTokenVerifier::new(AcceptingResolver);
        for value in [
            "Bearer",
            "Bearer  valid-token",
            "Bearer valid-token ",
            " Bearer valid-token",
            "Basic valid-token",
        ] {
            let error = verifier
                .verify(&metadata(value.as_bytes()))
                .expect_err("ambiguous or unsafe authorization must fail closed");
            assert_eq!(
                error.code,
                GatewayErrorCode::InvalidAuthorization,
                "{value:?}"
            );
        }

        assert!(verifier.verify(&metadata(b"bearer valid-token")).is_ok());
        assert!(verifier.verify(&metadata(b"BEARER valid-token")).is_ok());
    }
}
