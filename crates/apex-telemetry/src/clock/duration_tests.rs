use super::{ClockError, duration_ns, duration_us};

#[test]
fn preserves_one_seven_and_999_microseconds() {
    for (end, expected) in [(1_001_000, 1), (1_007_000, 7), (1_999_000, 999)] {
        assert_eq!(duration_us(1_000_000, end), Ok(expected));
    }
}

#[test]
fn subtracts_nanoseconds_before_truncating_microseconds() {
    for (start, end, nanos, micros) in [
        (0, 0, 0, 0),
        (999, 1_000, 1, 0),
        (999, 1_998, 999, 0),
        (999, 2_000, 1_001, 1),
    ] {
        assert_eq!(duration_ns(start, end), Ok(nanos));
        assert_eq!(duration_us(start, end), Ok(micros));
    }
}

#[test]
fn preserves_origins_and_durations_above_two_to_the_53() {
    assert_eq!(
        duration_us(9_007_199_254_740_993, 9_007_199_254_747_993),
        Ok(7)
    );
    assert_eq!(
        duration_us(999, 9_007_199_254_740_994_999),
        Ok(9_007_199_254_740_994),
    );
    assert_eq!(duration_ns(u128::MAX - 7_000, u128::MAX), Ok(7_000));
}

#[test]
fn rejects_reversed_intervals_including_wide_origins() {
    for (start, end) in [(1, 0), (1_001, 1_000), (u128::MAX, u128::MAX - 1)] {
        assert_eq!(duration_ns(start, end), Err(ClockError::MonotonicBackwards));
        assert_eq!(duration_us(start, end), Err(ClockError::MonotonicBackwards));
    }
}

#[test]
fn checks_nanosecond_u64_narrowing() {
    assert_eq!(duration_ns(0, 18_446_744_073_709_551_615), Ok(u64::MAX));
    assert_eq!(
        duration_ns(0, 18_446_744_073_709_551_616),
        Err(ClockError::Overflow)
    );
}

#[test]
fn narrows_microseconds_only_after_division() {
    assert_eq!(duration_us(0, 18_446_744_073_709_551_615_999), Ok(u64::MAX));
    assert_eq!(
        duration_us(0, 18_446_744_073_709_551_616_000),
        Err(ClockError::Overflow),
    );
    assert_eq!(duration_us(0, u128::MAX), Err(ClockError::Overflow));
}
