use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::{ClockError, ClockSource, WallClockSample};

/// Standard-library source for [`super::Clock::new`].
///
/// Elapsed reads must use `Instant::checked_duration_since` so a reversed read
/// remains an error. `SystemTime` is read only within the initial wall bracket.
/// Platform representation metadata is not a measured physical resolution or
/// verified UTC accuracy. No floating-point conversion is permitted.
/// Suspend behavior and clock rate can vary by platform; no drift bound is known.
/// The built-in metadata is qualified for Windows and Linux only.
#[derive(Debug)]
pub struct SystemClockSource {
    origin: Instant,
    resolution_ns: u64,
}

impl SystemClockSource {
    pub(super) fn new() -> Result<Self, ClockError> {
        // https://doc.rust-lang.org/std/time/struct.SystemTime.html
        // These are representation units, not measured hardware tick periods.
        let resolution_ns = if cfg!(windows) {
            100
        } else if cfg!(target_os = "linux") {
            1
        } else {
            return Err(ClockError::SourceUnavailable);
        };
        Ok(Self {
            origin: Instant::now(),
            resolution_ns,
        })
    }
}

impl ClockSource for SystemClockSource {
    fn source(&self) -> &str {
        "std::time::Instant with std::time::SystemTime wall anchor; representation estimate; UTC/drift unknown"
    }

    fn monotonic_now_ns(&mut self) -> Result<u128, ClockError> {
        instant_ns_since(self.origin, Instant::now())
    }

    fn wall_now(&mut self) -> Result<WallClockSample, ClockError> {
        let unix_ns = system_time_unix_ns(SystemTime::now())?;
        Ok(WallClockSample {
            unix_ns,
            resolution_ns: self.resolution_ns,
            // Budget one representation unit. Acquisition and final output
            // truncation are added by Clock. OS clock error/UTC sync, physical
            // tick cadence, rate changes and subsequent drift remain unknown.
            uncertainty_ns: Some(u128::from(self.resolution_ns)),
        })
    }
}

// Keep the wide Duration::as_nanos result intact. Clock checks u64 sample/epoch
// bounds after the appropriate unit conversion.
fn instant_ns_since(origin: Instant, sample: Instant) -> Result<u128, ClockError> {
    sample
        .checked_duration_since(origin)
        .map(|duration| duration.as_nanos())
        .ok_or(ClockError::MonotonicBackwards)
}

fn system_time_unix_ns(sample: SystemTime) -> Result<u128, ClockError> {
    sample
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| ClockError::BeforeUnixEpoch)
}

#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;
