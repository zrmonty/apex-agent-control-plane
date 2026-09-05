use super::*;
use crate::browser::oidc::verify::temporal::validate;

// Literal epoch seconds and independently specified expected expirations keep
// exact boundary assertions independent of signing latency and the wall clock.
const NOW: i64 = 1_788_480_000;

#[test]
fn issuance_exactly_thirty_seconds_ahead_is_accepted() {
    assert_eq!(
        validate(&json!({"iat": 1788480030, "exp": 1788480300}), NOW),
        Ok(1788480300)
    );
}

#[test]
fn issuance_thirty_one_seconds_ahead_is_rejected() {
    assert_eq!(
        validate(&json!({"iat": 1788480031, "exp": 1788480300}), NOW),
        Err(BrowserError::Unauthenticated)
    );
}

#[test]
fn expiration_must_be_strictly_after_now() {
    assert_eq!(
        validate(&json!({"iat": 1788479999, "exp": 1788480001}), NOW),
        Ok(1788480001)
    );
    assert_eq!(
        validate(&json!({"iat": 1788479999, "exp": 1788480000}), NOW),
        Err(BrowserError::Unauthenticated)
    );
}

#[test]
fn one_second_and_one_hour_lifetimes_are_accepted() {
    assert_eq!(
        validate(&json!({"iat": 1788480000, "exp": 1788480001}), NOW),
        Ok(1788480001)
    );
    assert_eq!(
        validate(&json!({"iat": 1788480000, "exp": 1788483600}), NOW),
        Ok(1788483600)
    );
}

#[test]
fn nonpositive_or_over_one_hour_lifetimes_are_rejected() {
    for value in [
        json!({"iat": 1788480001, "exp": 1788480001}),
        json!({"iat": 1788480002, "exp": 1788480001}),
        json!({"iat": 1788480000, "exp": 1788483601}),
    ] {
        assert_eq!(validate(&value, NOW), Err(BrowserError::Unauthenticated));
    }
}

#[test]
fn not_before_absent_past_and_exact_now_are_accepted() {
    let mut value = json!({"iat": 1788480000, "exp": 1788480300});
    assert_eq!(validate(&value, NOW), Ok(1788480300));
    for nbf in [i64::MIN, 1788479999, 1788480000] {
        value["nbf"] = json!(nbf);
        assert_eq!(validate(&value, NOW), Ok(1788480300));
    }
}

#[test]
fn not_before_one_second_ahead_gets_no_issuance_skew_allowance() {
    assert_eq!(
        validate(
            &json!({"iat": 1788480000, "exp": 1788480300, "nbf": 1788480001}),
            NOW
        ),
        Err(BrowserError::Unauthenticated)
    );
}

#[test]
fn integer_dates_preserve_precision_above_two_to_the_fifty_third() {
    assert_eq!(
        validate(
            &json!({"iat": 9007199254740993_i64, "exp": 9007199254740994_i64, "nbf": 9007199254740993_i64}),
            9007199254740993
        ),
        Ok(9007199254740994)
    );
    assert_eq!(
        validate(
            &json!({"iat": 9007199254740993_i64, "exp": 9007199254740994_i64, "nbf": 9007199254740994_i64}),
            9007199254740993
        ),
        Err(BrowserError::Unauthenticated)
    );
}

#[test]
fn near_i64_limit_can_validate_without_rounding_or_truncating() {
    assert_eq!(
        validate(
            &json!({"iat": 9223372036854775747_i64, "exp": 9223372036854775807_i64}),
            9223372036854775776
        ),
        Ok(9223372036854775807)
    );
}

#[test]
fn checked_time_arithmetic_overflow_and_negative_issuance_fail_closed() {
    for (value, now) in [
        (json!({"iat": i64::MIN, "exp": i64::MAX}), NOW),
        (
            json!({"iat": i64::MAX - 30, "exp": i64::MAX}),
            i64::MAX - 29,
        ),
        (json!({"iat": -1, "exp": 1}), 0),
    ] {
        assert_eq!(validate(&value, now), Err(BrowserError::Unauthenticated));
    }
}
