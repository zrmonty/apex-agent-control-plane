use super::test_support::{EPOCH_NS, EPOCH_US, Reading, ScriptedSource, clock, wall};
use super::{Clock, ClockError, ClockSnapshot, WallClockSample, duration_ns, duration_us};

#[test]
fn maps_exact_epoch_and_one_seven_999_microseconds() -> Result<(), ClockError> {
    let clock = clock(&[0, 0, 0, 1_000, 7_000, 999_000], wall(EPOCH_NS))?;
    assert_eq!(
        clock.now(),
        Ok(ClockSnapshot {
            monotonic_ns: 0,
            unix_us: 1_788_480_000_123_456,
            resolution_ns: 1,
            uncertainty_us: Some(0),
            source: "injected exact clock".into(),
        })
    );
    assert_eq!(clock.now()?.unix_us, 1_788_480_000_123_457);
    assert_eq!(clock.now()?.unix_us, 1_788_480_000_123_463);
    assert_eq!(clock.now()?.unix_us, 1_788_480_000_124_455);
    Ok(())
}

#[test]
fn combines_wall_remainder_and_elapsed_nanos_before_truncation() -> Result<(), ClockError> {
    let clock = clock(&[0, 0, 0, 1, 999], wall(1_788_480_000_123_456_999))?;
    let initial = clock.now()?;
    assert_eq!(
        (initial.unix_us, initial.uncertainty_us),
        (EPOCH_US, Some(1))
    );
    let carried = clock.now()?;
    assert_eq!(carried.monotonic_ns, 1);
    assert_eq!(
        (carried.unix_us, carried.uncertainty_us),
        (1_788_480_000_123_457, Some(0))
    );
    let fractional = clock.now()?;
    assert_eq!(fractional.monotonic_ns, 999);
    assert_eq!(
        (fractional.unix_us, fractional.uncertainty_us),
        (1_788_480_000_123_457, Some(1))
    );
    Ok(())
}

#[test]
fn preserves_large_epoch_and_monotonic_integers() -> Result<(), ClockError> {
    let clock = clock(
        &[
            9_007_199_254_740_993,
            9_007_199_254_740_993,
            9_007_199_254_747_993,
        ],
        wall(9_007_199_254_740_993_123_000),
    )?;
    let snapshot = clock.now()?;
    assert_eq!(snapshot.monotonic_ns, 9_007_199_254_747_993);
    assert_eq!(snapshot.unix_us, 9_007_199_254_740_993_130);
    Ok(())
}

#[test]
fn uses_floor_midpoint_and_ceiling_acquisition_radius() -> Result<(), ClockError> {
    let clock = clock(
        &[10_000, 15_001, 15_001, 15_500],
        WallClockSample {
            unix_ns: EPOCH_NS,
            resolution_ns: 2_500,
            uncertainty_ns: Some(17_000),
        },
    )?;
    // Midpoint 12_500; radius 2_501. At 15_001 the 501 discarded ns
    // contribute to ceil((17_000 + 2_501 + 501) / 1_000) = 21 us.
    let first = clock.now()?;
    assert_eq!(first.unix_us, 1_788_480_000_123_458);
    assert_eq!(first.resolution_ns, 2_500);
    assert_eq!(first.uncertainty_us, Some(21));
    let aligned = clock.now()?;
    assert_eq!(aligned.unix_us, 1_788_480_000_123_459);
    assert_eq!(aligned.uncertainty_us, Some(20));
    Ok(())
}

#[test]
fn rounds_combined_uncertainty_once() -> Result<(), ClockError> {
    let clock = clock(
        &[0, 1, 1],
        WallClockSample {
            uncertainty_ns: Some(998),
            ..wall(0)
        },
    )?;
    let snapshot = clock.now()?;
    assert_eq!(snapshot.unix_us, 0);
    assert_eq!(snapshot.uncertainty_us, Some(1)); // 998 + radius 1 + remainder 1.
    Ok(())
}

#[test]
fn keeps_unknown_uncertainty_unknown() -> Result<(), ClockError> {
    let clock = clock(
        &[0, 5_001, 5_001],
        WallClockSample {
            uncertainty_ns: None,
            ..wall(EPOCH_NS)
        },
    )?;
    assert_eq!(clock.now()?.uncertainty_us, None);
    Ok(())
}

#[test]
fn retains_zero_and_coarse_source_estimates_without_claiming_accuracy() -> Result<(), ClockError> {
    for (resolution_ns, uncertainty_ns, expected_us) in [(1, 0, 0), (1_000_000, 1_000_000, 1_000)] {
        let clock = clock(
            &[0, 0, 0],
            WallClockSample {
                resolution_ns,
                uncertainty_ns: Some(uncertainty_ns),
                ..wall(0)
            },
        )?;
        let snapshot = clock.now()?;
        assert_eq!(snapshot.resolution_ns, resolution_ns);
        assert_eq!(snapshot.uncertainty_us, Some(expected_us));
    }
    Ok(())
}

#[test]
fn rejects_backwards_bracket_and_first_sample_before_bracket_end() -> Result<(), ClockError> {
    assert!(matches!(
        Clock::with_source(ScriptedSource::new(&[2, 1], wall(0))),
        Err(ClockError::MonotonicBackwards),
    ));
    let clock = clock(&[0, 2_000, 1_999], wall(0))?;
    assert_eq!(clock.now(), Err(ClockError::MonotonicBackwards));
    Ok(())
}

#[test]
fn rejects_regression_without_moving_last_accepted_sample() -> Result<(), ClockError> {
    let clock = clock(&[0, 0, 7_000, 6_999, 6_999, 7_000], wall(EPOCH_NS))?;
    let first = clock.now()?;
    assert_eq!(clock.now(), Err(ClockError::MonotonicBackwards));
    assert_eq!(clock.now(), Err(ClockError::MonotonicBackwards));
    assert_eq!(clock.now(), Ok(first));
    Ok(())
}

#[test]
fn bounds_source_labels_in_bytes_and_rejects_blank_or_control_text() {
    for label in [
        "".into(),
        "   ".into(),
        "x".repeat(257),
        "é".repeat(129),
        "clock\nlabel".into(),
    ] {
        let mut source = ScriptedSource::new(&[0, 0], wall(0));
        source.label = label;
        assert!(matches!(
            Clock::with_source(source),
            Err(ClockError::InvalidMetadata)
        ));
    }
}

#[test]
fn accepts_bounded_unicode_labels_and_copies_metadata() -> Result<(), ClockError> {
    for label in ["x".repeat(256), "é".repeat(128)] {
        let mut source = ScriptedSource::new(&[0, 0, 0], wall(0));
        source.label = label.clone();
        assert_eq!(Clock::with_source(source)?.now()?.source, label);
    }
    Ok(())
}

#[test]
fn rejects_zero_resolution_at_construction() {
    let source = ScriptedSource::new(
        &[0, 0],
        WallClockSample {
            resolution_ns: 0,
            ..wall(0)
        },
    );
    assert!(matches!(
        Clock::with_source(source),
        Err(ClockError::InvalidMetadata)
    ));
}

#[test]
fn rejects_wall_epochs_outside_u64_microseconds() {
    for unix_ns in [18_446_744_073_709_551_616_000, u128::MAX] {
        let source = ScriptedSource::new(&[0, 0], wall(unix_ns));
        assert!(matches!(
            Clock::with_source(source),
            Err(ClockError::Overflow)
        ));
    }
}

#[test]
fn accepts_u64_epoch_limit_until_elapsed_carry_exceeds_it() -> Result<(), ClockError> {
    let clock = clock(&[0, 0, 0, 1], wall(18_446_744_073_709_551_615_999))?;
    assert_eq!(clock.now()?.unix_us, u64::MAX);
    assert_eq!(clock.now(), Err(ClockError::Overflow));
    Ok(())
}

#[test]
fn checks_monotonic_u64_bounds_at_both_bracket_reads_and_now() -> Result<(), ClockError> {
    let too_large = 18_446_744_073_709_551_616;
    for samples in [[too_large, too_large], [0, too_large]] {
        assert!(matches!(
            Clock::with_source(ScriptedSource::new(&samples, wall(0))),
            Err(ClockError::Overflow)
        ));
    }
    let clock = clock(&[0, 0, too_large], wall(0))?;
    assert_eq!(clock.now(), Err(ClockError::Overflow));
    Ok(())
}

#[test]
fn avoids_overflow_when_bracket_endpoints_sum_above_u64_max() -> Result<(), ClockError> {
    let clock = clock(
        &[
            18_446_744_073_709_546_614,
            18_446_744_073_709_551_615,
            18_446_744_073_709_551_615,
        ],
        wall(EPOCH_NS),
    )?;
    let snapshot = clock.now()?;
    assert_eq!(snapshot.monotonic_ns, u64::MAX);
    assert_eq!(snapshot.unix_us, 1_788_480_000_123_458);
    assert_eq!(snapshot.uncertainty_us, Some(4)); // ceil((2_501 + 501) / 1_000).
    Ok(())
}

#[test]
fn handles_full_u64_acquisition_window_without_ceil_overflow() -> Result<(), ClockError> {
    let clock = clock(&[0, u128::from(u64::MAX), u128::from(u64::MAX)], wall(0))?;
    let snapshot = clock.now()?;
    assert_eq!(snapshot.unix_us, 9_223_372_036_854_775);
    assert_eq!(snapshot.uncertainty_us, Some(9_223_372_036_854_777));
    Ok(())
}

#[test]
fn checks_uncertainty_addition_and_u64_narrowing() -> Result<(), ClockError> {
    for uncertainty_ns in [18_446_744_073_709_551_616_000, u128::MAX] {
        let source = ScriptedSource::new(
            &[0, 1],
            WallClockSample {
                uncertainty_ns: Some(uncertainty_ns),
                ..wall(0)
            },
        );
        assert!(matches!(
            Clock::with_source(source),
            Err(ClockError::Overflow)
        ));
    }
    let clock = clock(
        &[0, 0, 0, 1],
        WallClockSample {
            uncertainty_ns: Some(18_446_744_073_709_551_615_000),
            ..wall(0)
        },
    )?;
    assert_eq!(clock.now()?.uncertainty_us, Some(u64::MAX));
    assert_eq!(clock.now(), Err(ClockError::Overflow));
    Ok(())
}

#[test]
fn propagates_errors_from_each_anchor_read() {
    let cases = [
        vec![Reading::Monotonic(Err(ClockError::Overflow))],
        vec![
            Reading::Monotonic(Ok(0)),
            Reading::Wall(Err(ClockError::BeforeUnixEpoch)),
        ],
        vec![
            Reading::Monotonic(Ok(0)),
            Reading::Wall(Ok(wall(0))),
            Reading::Monotonic(Err(ClockError::MonotonicBackwards)),
        ],
    ];
    for (readings, expected) in cases.into_iter().zip([
        ClockError::Overflow,
        ClockError::BeforeUnixEpoch,
        ClockError::MonotonicBackwards,
    ]) {
        let source = ScriptedSource {
            readings: readings.into(),
            label: "failing source".into(),
        };
        assert!(matches!(Clock::with_source(source), Err(error) if error == expected));
    }
}

#[test]
fn propagates_read_failure_without_poisoning_or_reanchoring() -> Result<(), ClockError> {
    let mut source = ScriptedSource::new(&[0, 0], wall(EPOCH_NS));
    source.readings.extend([
        Reading::Monotonic(Err(ClockError::SourceUnavailable)),
        Reading::Monotonic(Ok(7_000)),
    ]);
    let clock = Clock::with_source(source)?;
    assert_eq!(clock.now(), Err(ClockError::SourceUnavailable));
    assert_eq!(clock.now()?.unix_us, 1_788_480_000_123_463);
    Ok(())
}

#[test]
fn overlapping_call_durations_keep_their_own_start_samples() -> Result<(), ClockError> {
    let clock = clock(&[0, 0, 1_000, 2_000, 5_000, 8_000], wall(EPOCH_NS))?;
    let a_start = clock.now()?;
    let b_start = clock.now()?;
    let a_end = clock.now()?;
    let b_end = clock.now()?;
    assert_eq!(
        duration_us(a_start.monotonic_ns.into(), a_end.monotonic_ns.into()),
        Ok(4)
    );
    assert_eq!(
        duration_us(b_start.monotonic_ns.into(), b_end.monotonic_ns.into()),
        Ok(6)
    );
    assert_eq!(
        duration_ns(a_start.monotonic_ns.into(), b_start.monotonic_ns.into()),
        Ok(1_000)
    );
    Ok(())
}

#[test]
fn output_conversion_failure_does_not_advance_or_reset_accepted_time() -> Result<(), ClockError> {
    let clock = clock(
        &[0, 0, 7_000, 7_001, 6_999, 7_000, 8_000],
        WallClockSample { uncertainty_ns: Some(u128::from(u64::MAX) * 1_000), ..wall(0) },
    )?;
    let first = clock.now()?;
    assert_eq!(clock.now(), Err(ClockError::Overflow));
    assert_eq!(clock.now(), Err(ClockError::MonotonicBackwards));
    assert_eq!(clock.now()?, first);
    assert_eq!(clock.now()?.unix_us, 8);
    Ok(())
}
