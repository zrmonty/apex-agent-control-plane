use std::time::{Duration, Instant, UNIX_EPOCH};

use super::{instant_ns_since, system_time_unix_ns};
use crate::clock::{Clock, ClockError};

#[test]
fn instant_conversion_detects_reversal_instead_of_saturating() -> Result<(), ClockError> {
    let origin = Instant::now();
    let later = origin
        .checked_add(Duration::from_nanos(7_001))
        .ok_or(ClockError::Overflow)?;
    assert_eq!(instant_ns_since(origin, later), Ok(7_001));
    assert_eq!(
        instant_ns_since(later, origin),
        Err(ClockError::MonotonicBackwards)
    );
    assert_eq!(instant_ns_since(origin, origin), Ok(0));
    Ok(())
}

#[test]
fn system_time_conversion_keeps_exact_epoch_and_submicrosecond_nanos() -> Result<(), ClockError> {
    let epoch = UNIX_EPOCH
        .checked_add(Duration::new(1_788_480_000, 123_456_700))
        .ok_or(ClockError::Overflow)?;
    // 700 ns is representable by both Windows' 100-ns and Linux's ns forms.
    assert_eq!(system_time_unix_ns(epoch), Ok(1_788_480_000_123_456_700));
    assert_eq!(system_time_unix_ns(UNIX_EPOCH), Ok(0));
    Ok(())
}

#[test]
fn system_time_before_epoch_returns_error() -> Result<(), ClockError> {
    let before = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .ok_or(ClockError::Overflow)?;
    assert_eq!(
        system_time_unix_ns(before),
        Err(ClockError::BeforeUnixEpoch)
    );
    Ok(())
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn production_clock_returns_ordered_samples_with_honest_source_metadata() -> Result<(), ClockError>
{
    let result = Clock::new();
    assert!(
        result.is_ok(),
        "production clock construction failed: {:?}",
        result.as_ref().err()
    );
    let clock = result?;
    let first = clock.now()?;
    let second = clock.now()?;
    assert!(second.monotonic_ns >= first.monotonic_ns);
    assert!(second.unix_us >= first.unix_us);
    assert!(first.resolution_ns > 0);
    assert!(first.source.contains("Instant"));
    assert!(first.source.contains("SystemTime"));
    assert!(first.source.len() <= 256);
    assert_eq!(first.resolution_ns, second.resolution_ns);
    // Source metadata estimates local representation/acquisition error only.
    // This smoke test asserts no tick size, elapsed time, or UTC accuracy.
    Ok(())
}

#[test]
#[cfg(not(any(windows, target_os = "linux")))]
fn unsupported_platform_has_no_invented_production_metadata() {
    assert!(matches!(Clock::new(), Err(ClockError::SourceUnavailable)));
}

#[test]
#[cfg(any(windows, target_os = "linux"))]
fn production_metadata_matches_declared_representation_not_utc_accuracy() -> Result<(), ClockError> {
    use crate::clock::{ClockSource, SystemClockSource};
    let mut source = SystemClockSource::new()?;
    let wall = source.wall_now()?;
    let expected = if cfg!(windows) { 100 } else { 1 };
    assert_eq!(wall.resolution_ns, expected);
    assert_eq!(wall.uncertainty_ns, Some(u128::from(expected)));
    assert!(source.source().contains("representation estimate"));
    assert!(source.source().contains("UTC/drift unknown"));
    Ok(())
}
