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

// `record_distributed_failure`/`distributed_deny_hint_active` use
// `tokio::task::block_in_place`, which requires running inside a task
// driven by a multi-thread Tokio runtime (matching production: the gateway
// runtime is built with `worker_threads(4)`). Only tests that attach an
// ephemeral store exercise that code path -- the rest never touch it and
// stay plain `#[test]`s.
#[tokio::test(flavor = "multi_thread")]
async fn distributed_deny_hint_is_shared_across_verifier_instances() {
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

#[tokio::test(flavor = "multi_thread")]
async fn ephemeral_store_errors_do_not_block_authentication() {
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

/// `accelerator_slots` bounds concurrent blocking-thread round trips into
/// the shared store; it says nothing about any individual identity's own
/// budget. Saturating it must degrade `record_distributed_failure` and
/// `distributed_deny_hint_active` to "no distributed signal this attempt"
/// -- the same as an unreachable store -- rather than blocking this call or
/// turning the accelerator's own concurrency limit into a rejection. Mirrors
/// control-plane-api's saturated-accelerator fallback test.
#[tokio::test(flavor = "multi_thread")]
async fn accelerator_slots_saturation_degrades_the_distributed_signal_without_blocking() {
    use crate::{EphemeralStore, InMemoryEphemeralStore};

    let store: Arc<Mutex<Box<dyn EphemeralStore>>> =
        Arc::new(Mutex::new(Box::new(InMemoryEphemeralStore::new())));
    let verifier = BearerTokenVerifier::new(RejectingResolver).with_ephemeral_store(store);
    // Hold every accelerator concurrency slot for the whole test, without
    // touching the process-local bucket map at all.
    let _permits = verifier
        .accelerator_slots
        .clone()
        .try_acquire_many_owned(MAX_ACCELERATOR_AUTH_OPERATIONS as u32)
        .expect("nothing else has acquired a permit yet");
    // The local-authoritative path must still decide the call on its own
    // budget -- first failure for a fresh identity is Unauthenticated, not
    // an internal error or a hang, even though the distributed counter and
    // deny-hint check can make zero progress.
    assert_eq!(
        verifier
            .verify(&metadata(b"Bearer saturated-accelerator"))
            .unwrap_err()
            .code,
        GatewayErrorCode::Unauthenticated
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


