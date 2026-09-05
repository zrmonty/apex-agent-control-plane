use super::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

// Real signatures and resolvers, but controlled samples at the composition
// boundary: no sleeps or race-prone one-second signed-token fixtures.
fn fixture() -> (TokenMaterial, i64) {
    let access = access_claims();
    let start = access["exp"].as_i64().unwrap() - 200;
    (material(access, "subject-123"), start)
}

fn sampled(
    input: TokenMaterial,
    started: i64,
    first: Result<i64, BrowserError>,
    last: Result<i64, BrowserError>,
) -> Result<VerifiedProviderTokens, BrowserError> {
    let first_read = Cell::new(true);
    let clock = || {
        if first_read.replace(false) {
            first
        } else {
            last
        }
    };
    validate_exchange_with_clock(
        &config(),
        input,
        &verifier(),
        &resolver(),
        IdTokenExpectation::Login { nonce: NONCE },
        started,
        clock,
    )
}

struct AdvancingResolver {
    inner: KeycloakOperatorCredentialResolver,
    now: AtomicI64,
    finished_at: i64,
    completed: AtomicBool,
}

impl OperatorCredentialResolver for AdvancingResolver {
    fn resolve(&self, token: &str) -> Result<crate::OperatorCaller, crate::CommandError> {
        let caller = self.inner.resolve(token)?;
        // Advance only after real access-token authentication succeeds.
        self.now.store(self.finished_at, Ordering::SeqCst);
        self.completed.store(true, Ordering::SeqCst);
        Ok(caller)
    }
}

fn sampled_after_resolution(
    input: TokenMaterial,
    started: i64,
    finished_at: i64,
) -> Result<VerifiedProviderTokens, BrowserError> {
    let authority = AdvancingResolver {
        inner: resolver(),
        now: AtomicI64::new(started),
        finished_at,
        completed: AtomicBool::new(false),
    };
    let first_sample = Cell::new(None);
    let last_sample = Cell::new(None);
    let result = validate_exchange_with_clock(
        &config(),
        input,
        &verifier(),
        &authority,
        IdTokenExpectation::Login { nonce: NONCE },
        started,
        || {
            let sample = (
                authority.completed.load(Ordering::SeqCst),
                authority.now.load(Ordering::SeqCst),
            );
            if first_sample.get().is_none() {
                first_sample.set(Some(sample));
            }
            last_sample.set(Some(sample));
            Ok(sample.1)
        },
    );
    assert!(
        authority.completed.load(Ordering::SeqCst),
        "the real fixture resolver must authenticate successfully"
    );
    assert_eq!(
        first_sample.get(),
        Some((false, started)),
        "the initial clock sample must precede authority resolution"
    );
    assert_eq!(
        last_sample.get(),
        Some((true, finished_at)),
        "the fresh clock sample must follow completed authority resolution"
    );
    result
}

#[test]
fn copied_access_expiry_at_fresh_end_time_is_not_live() {
    let (mut input, start) = fixture();
    input.access_lifetime = 1;
    let result = sampled_after_resolution(input, start, start + 1);
    assert_eq!(result.unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn signed_access_expiry_at_fresh_end_time_is_not_live() {
    let (input, original_start) = fixture();
    // Signed expiry is original_start + 200. Only five seconds of the
    // composition window elapse, so its age guard cannot hide an expiry bug.
    let start = original_start + 195;
    let result = sampled_after_resolution(input, start, original_start + 200);
    assert_eq!(result.unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn copied_refresh_expiry_at_fresh_end_time_is_not_live() {
    let (mut input, start) = fixture();
    input.refresh_lifetime = 1;
    let result = sampled_after_resolution(input, start, start + 1);
    assert_eq!(result.unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn live_final_sample_preserves_start_anchored_expiries_without_copying_leeway() {
    let (mut input, start) = fixture();
    input.access_lifetime = 60;
    let result = sampled_after_resolution(input, start, start + 5).unwrap();
    assert_eq!(result.access_expires_at, start + 60);
    assert_eq!(result.refresh_expires_at, start + 1800);
}

#[test]
fn fresh_end_age_exactly_ten_seconds_is_allowed() {
    let (input, start) = fixture();
    assert!(sampled(input, start, Ok(start), Ok(start + 10)).is_ok());
}

#[test]
fn fresh_end_age_over_ten_seconds_is_rejected_even_with_live_tokens() {
    let (input, start) = fixture();
    let result = sampled(input, start, Ok(start), Ok(start + 11));
    assert_eq!(result.unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn end_clock_rollback_within_the_start_window_is_rejected() {
    let (input, start) = fixture();
    let result = sampled(input, start, Ok(start + 5), Ok(start + 4));
    assert_eq!(result.unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn end_clock_before_start_negative_or_overflowing_age_fails_closed() {
    for offset in [Some(-1), None] {
        let (input, start) = fixture();
        let last = offset.map_or(i64::MIN, |offset| start + offset);
        assert_eq!(
            sampled(input, start, Ok(start), Ok(last)).unwrap_err(),
            BrowserError::Unauthenticated
        );
    }
    let (input, start) = fixture();
    assert_eq!(
        sampled(input, start, Ok(start), Ok(-1)).unwrap_err(),
        BrowserError::Unauthenticated
    );
}

#[test]
fn fresh_end_clock_read_failure_is_unavailable_and_never_returns_material() {
    let (input, start) = fixture();
    let error = sampled(input, start, Ok(start), Err(BrowserError::Unavailable)).unwrap_err();
    assert_eq!(error, BrowserError::Unavailable);
    assert!(!format!("{error:?} {error}").contains("canary"));
}

#[test]
fn initial_clock_read_failure_still_fails_before_authority_resolution() {
    struct MustNotResolve;
    impl OperatorCredentialResolver for MustNotResolve {
        fn resolve(&self, _: &str) -> Result<crate::OperatorCaller, crate::CommandError> {
            panic!("unavailable clock must fail before authority resolution")
        }
    }
    let (input, start) = fixture();
    let result = validate_exchange_with_clock(
        &config(),
        input,
        &verifier(),
        &MustNotResolve,
        IdTokenExpectation::Login { nonce: NONCE },
        start,
        || Err(BrowserError::Unavailable),
    );
    assert_eq!(result.unwrap_err(), BrowserError::Unavailable);
}
