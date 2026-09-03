//! Per-operator admission/rate-limiting tests, exercised through
//! `SubmitCommand` -- the only RPC that charges the ceiling this module
//! covers. See `service.rs`'s own `admit`/`admit_locally` doc for the
//! shared-store-then-local-floor contract these tests pin.

use crate::auth::StaticOperatorTokenResolver;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

/// Two independent services sharing one `EphemeralStore`, which is what a
/// two-replica deployment sharing one Valkey looks like from the admission
/// path's point of view.
fn replica_pair(
    limit: u32,
    store: Option<SharedEphemeralStore>,
) -> (
    ControlGatewayService<StaticOperatorTokenResolver>,
    ControlGatewayService<StaticOperatorTokenResolver>,
) {
    let build = || {
        let service = service().with_admission_limits(limit, std::time::Duration::from_secs(60));
        match &store {
            Some(store) => service.with_ephemeral_store(Arc::clone(store)),
            None => service,
        }
    };
    (build(), build())
}

async fn accepted_across(
    replicas: &(
        ControlGatewayService<StaticOperatorTokenResolver>,
        ControlGatewayService<StaticOperatorTokenResolver>,
    ),
    attempts: u64,
) -> usize {
    let mut accepted = 0;
    for index in 0..attempts {
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(0x5000 + index));
        let response = if index % 2 == 0 {
            replicas.0.submit_command(authed_request(request)).await
        } else {
            replicas.1.submit_command(authed_request(request)).await
        };
        if response.is_ok() {
            accepted += 1;
        }
    }
    accepted
}

/// The defect this closes. Two replicas with only process-local buckets
/// admit twice the configured ceiling, which means the admission control
/// added in the first pass quietly weakened the moment the Postgres outbox
/// made multiple replicas safe to run.
#[tokio::test]
async fn two_replicas_without_a_shared_store_admit_twice_the_ceiling() {
    let replicas = replica_pair(8, None);
    assert_eq!(accepted_across(&replicas, 64).await, 16);
}

/// ... and with the shared store attached, the *combined* admission across
/// both replicas is the configured ceiling, not twice it.
#[tokio::test]
async fn two_replicas_sharing_a_store_are_bounded_to_one_ceiling_between_them() {
    let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(
        apex_auth::InMemoryEphemeralStore::new(),
    )));
    let replicas = replica_pair(8, Some(store));
    assert_eq!(accepted_across(&replicas, 64).await, 8);
}

/// An accelerator that answers `Unavailable` for everything must leave the
/// process-local ceiling in charge -- neither failing open (admitting
/// everything) nor failing shut (admitting nothing). This is the in-process
/// half of the live Valkey-outage test.
#[tokio::test]
async fn a_dead_shared_store_falls_back_to_the_local_ceiling_rather_than_failing_open() {
    struct DeadStore;
    impl apex_auth::EphemeralStore for DeadStore {
        fn check_rate_limit(
            &mut self,
            _key: &RateLimitKey,
            _limit: u32,
            _window: Duration,
        ) -> Result<apex_auth::RateLimitDecision, apex_auth::EphemeralError> {
            Err(apex_auth::EphemeralError::unavailable())
        }
        fn increment_fingerprint(
            &mut self,
            _key: &apex_auth::FingerprintCounterKey,
            _window: Duration,
        ) -> Result<u64, apex_auth::EphemeralError> {
            Err(apex_auth::EphemeralError::unavailable())
        }
        fn fingerprint_count(
            &mut self,
            _key: &apex_auth::FingerprintCounterKey,
        ) -> Result<u64, apex_auth::EphemeralError> {
            Err(apex_auth::EphemeralError::unavailable())
        }
        fn set_deny_hint(
            &mut self,
            _key: &apex_auth::DenyHintKey,
            _ttl: Duration,
        ) -> Result<(), apex_auth::EphemeralError> {
            Err(apex_auth::EphemeralError::unavailable())
        }
        fn is_denied(
            &mut self,
            _key: &apex_auth::DenyHintKey,
        ) -> Result<bool, apex_auth::EphemeralError> {
            Err(apex_auth::EphemeralError::unavailable())
        }
    }
    let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(DeadStore)));
    let replicas = replica_pair(8, Some(store));
    // Each replica's own ceiling still applies: 8 + 8, never 64.
    assert_eq!(accepted_across(&replicas, 64).await, 16);
}

/// The shared store may only ever deny. A store that reports "allowed" for
/// everything must not lift the process-local ceiling.
#[tokio::test]
async fn a_permissive_shared_store_cannot_raise_the_local_ceiling() {
    struct AlwaysAllow;
    impl apex_auth::EphemeralStore for AlwaysAllow {
        fn check_rate_limit(
            &mut self,
            _key: &RateLimitKey,
            limit: u32,
            _window: Duration,
        ) -> Result<apex_auth::RateLimitDecision, apex_auth::EphemeralError> {
            Ok(apex_auth::RateLimitDecision {
                allowed: true,
                remaining: limit,
            })
        }
        fn increment_fingerprint(
            &mut self,
            _key: &apex_auth::FingerprintCounterKey,
            _window: Duration,
        ) -> Result<u64, apex_auth::EphemeralError> {
            Ok(0)
        }
        fn fingerprint_count(
            &mut self,
            _key: &apex_auth::FingerprintCounterKey,
        ) -> Result<u64, apex_auth::EphemeralError> {
            Ok(0)
        }
        fn set_deny_hint(
            &mut self,
            _key: &apex_auth::DenyHintKey,
            _ttl: Duration,
        ) -> Result<(), apex_auth::EphemeralError> {
            Ok(())
        }
        fn is_denied(
            &mut self,
            _key: &apex_auth::DenyHintKey,
        ) -> Result<bool, apex_auth::EphemeralError> {
            Ok(false)
        }
    }
    let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(AlwaysAllow)));
    let replicas = replica_pair(8, Some(store));
    assert_eq!(accepted_across(&replicas, 64).await, 16);
}

/// `accelerator_slots` bounds how many blocking-thread round trips into the
/// shared store run at once; it says nothing about any individual subject's
/// own admission. Saturating it must degrade to the local ceiling exactly
/// like an unreachable or lock-poisoned store (the test above), not reject
/// an admission the local ceiling would have allowed just because unrelated
/// callers currently hold every permit.
#[tokio::test]
async fn a_saturated_accelerator_concurrency_limit_falls_back_to_the_local_ceiling_rather_than_failing_shut()
 {
    let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(
        apex_auth::InMemoryEphemeralStore::new(),
    )));
    let service = service()
        .with_admission_limits(8, std::time::Duration::from_secs(60))
        .with_ephemeral_store(store);
    // Hold every accelerator concurrency slot for the whole test, without
    // touching the process-local ceiling at all.
    let _permits = service
        .accelerator_slots
        .clone()
        .try_acquire_many_owned(MAX_ACCELERATOR_OPERATIONS as u32)
        .expect("nothing else has acquired a permit yet");
    for index in 0..8 {
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(0x6000 + index));
        service
            .submit_command(authed_request(request))
            .await
            .expect(
                "admission within the local ceiling must succeed even while the \
                 accelerator's concurrency limiter is saturated",
            );
    }
    let mut request = stop_request();
    request.command_id = Some(fresh_command_id(0x6100));
    let status = service
        .submit_command(authed_request(request))
        .await
        .expect_err("the local ceiling itself must still apply");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

/// The control gateway's admission counters must be unreachable from the
/// ingest workload's keyspace. `event-ingest` keys its own admission
/// bucket on the envelope's `workspace_id` (or `unscoped`); this namespace
/// is a value it cannot produce without someone deliberately creating a
/// workspace by that name, and the deployment profile pins the ACL key
/// pattern to it as well.
#[test]
fn the_admission_key_is_namespaced_away_from_the_ingest_workload() {
    let key = control_admission_rate_limit_key("operator:keycloak:abc");
    assert_eq!(key.namespace, CONTROL_ADMISSION_NAMESPACE);
    assert_ne!(key.namespace, "unscoped");
    // The subject never appears in the key.
    assert!(!key.bucket.contains("operator"));
    assert!(!key.bucket.contains("abc"));
    // Distinct operators get distinct buckets; the same operator is stable.
    assert_ne!(
        control_admission_rate_limit_key("operator:keycloak:one").bucket,
        control_admission_rate_limit_key("operator:keycloak:two").bucket
    );
    assert_eq!(
        control_admission_rate_limit_key("operator:keycloak:one").bucket,
        control_admission_rate_limit_key("operator:keycloak:one").bucket
    );
    // Both components have to satisfy the store's own key grammar, or
    // every check_rate_limit call would fail InvalidKey and the shared
    // ceiling would silently never apply.
    let mut store = apex_auth::InMemoryEphemeralStore::new();
    assert!(
        store
            .check_rate_limit(&key, 1, Duration::from_secs(1))
            .is_ok()
    );
}
