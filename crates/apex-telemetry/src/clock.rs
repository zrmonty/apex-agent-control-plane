//! A fixed wall anchor with monotonic elapsed time and checked integer units.
//!
//! Reuse one clock for a process mapping; snapshots from separate clocks do not
//! share a monotonic origin. This module creates no global clock or stage state.
//! Wall metadata describes representation and local acquisition estimates, not
//! verified UTC synchronization, physical tick resolution, or later drift.

use std::fmt;
use std::sync::Mutex;

mod system;
pub use system::SystemClockSource;

const NS_PER_US: u128 = 1_000;

/// A recoverable sampling, metadata, or integer-conversion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// A monotonic read predates its origin, bracket end, or prior accepted read.
    MonotonicBackwards,
    /// Arithmetic or a required `u64` conversion cannot represent the value.
    Overflow,
    /// Source text is blank, contains controls, exceeds 256 bytes, or resolution is zero.
    InvalidMetadata,
    /// A system wall sample predates the Unix epoch.
    BeforeUnixEpoch,
    /// The clock's sampling state was poisoned by an unwinding source.
    Poisoned,
    /// The injected or platform source could not supply a sample.
    SourceUnavailable,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MonotonicBackwards => "monotonic clock moved backwards",
            Self::Overflow => "clock integer overflow",
            Self::InvalidMetadata => "invalid clock source metadata",
            Self::BeforeUnixEpoch => "wall clock is before the Unix epoch",
            Self::Poisoned => "clock sampling state is poisoned",
            Self::SourceUnavailable => "clock source is unavailable",
        })
    }
}

impl std::error::Error for ClockError {}

/// Raw wall reading supplied at the OS boundary and validated by the clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WallClockSample {
    /// Exact Unix nanoseconds; widened before arithmetic and narrowed after division.
    pub unix_ns: u128,
    /// Positive declared wall representation granularity, not physical accuracy.
    pub resolution_ns: u64,
    /// Source representation/conversion error estimate in ns, excluding bracket
    /// acquisition and final ns-to-us truncation. `None` means unknown.
    pub uncertainty_ns: Option<u128>,
}

/// Injectable clock boundary. Only the clock may sample its owned source.
///
/// Implementations must return readings in acquisition order. Mutable methods
/// permit simple deterministic sources that are `Send` but not `Sync`; the clock
/// serializes acquisition and last-sample validation under the same mutex.
/// Sources must not reenter their owning clock. Source labels and wall metadata
/// are captured at construction and never reread by [`Clock::now`].
pub trait ClockSource: Send {
    /// A nonblank label of at most 256 UTF-8 bytes without control characters.
    fn source(&self) -> &str;

    /// Read monotonic nanoseconds in this source's origin.
    ///
    /// # Errors
    /// Return a source failure, reversed-origin error, or conversion overflow.
    fn monotonic_now_ns(&mut self) -> Result<u128, ClockError>;

    /// Read exact Unix wall nanoseconds and declared local source metadata.
    ///
    /// # Errors
    /// Return a source failure, pre-epoch wall error, or conversion overflow.
    fn wall_now(&mut self) -> Result<WallClockSample, ClockError>;
}

/// Integer clock output. This is plain measurement data, not access authority.
///
/// No clock API accepts a caller-constructed snapshot as an anchor or state.
/// Wire consumers must preserve the integers as integer fields or decimal text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSnapshot {
    /// Source-origin monotonic nanoseconds, also retained for sub-us durations.
    pub monotonic_ns: u64,
    /// Unix microseconds, truncated once after adding the wall and elapsed ns.
    pub unix_us: u64,
    /// Wall anchor representation granularity, not elapsed-clock resolution.
    pub resolution_ns: u64,
    /// Ceil of source error + acquisition radius + discarded output ns, in us.
    /// Unknown source error stays `None`. Excludes UTC/sync error and later drift.
    pub uncertainty_us: Option<u64>,
    /// The bounded source label captured during construction.
    pub source: String,
}

/// A clock with one immutable epoch mapping and serialized sample acquisition.
#[derive(Debug)]
pub struct Clock<S: ClockSource = SystemClockSource> {
    anchor_ns: u64,
    anchor_unix_ns: u128,
    resolution_ns: u64,
    anchor_uncertainty_ns: Option<u128>,
    source_label: String,
    state: Mutex<SamplingState<S>>,
}

#[derive(Debug)]
struct SamplingState<S> {
    source: S,
    last_ns: u64,
}

impl Clock<SystemClockSource> {
    /// Construct the production `Instant` + `SystemTime` bracketed clock.
    ///
    /// # Errors
    /// Returns source, bracket, wall, metadata, or integer-conversion errors.
    /// The built-in source supports Windows and Linux; other targets return
    /// [`ClockError::SourceUnavailable`] until their metadata is qualified.
    pub fn new() -> Result<Self, ClockError> {
        Self::with_source(SystemClockSource::new()?)
    }
}

impl<S: ClockSource> Clock<S> {
    /// Capture `before -> wall -> after`, binding wall ns to the floor midpoint.
    ///
    /// The acquisition radius is the ceiling half-width. The first subsequent
    /// sample must be at least `after`. Wall and source metadata never reanchor.
    ///
    /// # Errors
    /// Rejects invalid metadata, reversed/out-of-range bracket reads, epochs or
    /// acquisition/source estimates outside `u64` microseconds, and source errors.
    pub fn with_source(mut source: S) -> Result<Self, ClockError> {
        let label = source.source();
        if label.len() > 256 || label.trim().is_empty() || label.chars().any(char::is_control) {
            return Err(ClockError::InvalidMetadata);
        }
        let source_label = label.to_owned();

        // The source is exclusively owned during construction. Preserve this
        // order: neither metadata processing nor another wall read reanchors it.
        let before_ns = narrow_u64(source.monotonic_now_ns()?)?;
        let wall = source.wall_now()?;
        let after_ns = narrow_u64(source.monotonic_now_ns()?)?;
        let window_ns = after_ns
            .checked_sub(before_ns)
            .ok_or(ClockError::MonotonicBackwards)?;
        if wall.resolution_ns == 0 {
            return Err(ClockError::InvalidMetadata);
        }
        narrow_u64(wall.unix_ns / NS_PER_US)?;

        let anchor_ns = before_ns
            .checked_add(window_ns / 2)
            .ok_or(ClockError::Overflow)?;
        // ceil(window / 2) without adding one to a possibly maximal window.
        let radius_ns = u128::from(window_ns / 2)
            .checked_add(u128::from(window_ns % 2))
            .ok_or(ClockError::Overflow)?;
        let anchor_uncertainty_ns = wall
            .uncertainty_ns
            .map(|ns| ns.checked_add(radius_ns).ok_or(ClockError::Overflow))
            .transpose()?;
        if let Some(ns) = anchor_uncertainty_ns {
            ceil_microseconds(ns)?;
        }

        Ok(Self {
            anchor_ns,
            anchor_unix_ns: wall.unix_ns,
            resolution_ns: wall.resolution_ns,
            anchor_uncertainty_ns,
            source_label,
            state: Mutex::new(SamplingState {
                source,
                last_ns: after_ns,
            }),
        })
    }

    /// Read, validate, and map one sample while holding the sampling state mutex.
    ///
    /// # Errors
    /// Returns source failure, poison, regression, arithmetic, or narrowing errors.
    /// Reversed/rejected reads must not lower the last accepted monotonic value.
    pub fn now(&self) -> Result<ClockSnapshot, ClockError> {
        // Acquire before reading the source: locking only the validation would
        // allow threads to acquire and validate samples in different orders.
        let mut state = self.state.lock().map_err(|_| ClockError::Poisoned)?;
        let monotonic_ns = narrow_u64(state.source.monotonic_now_ns()?)?;
        if monotonic_ns < state.last_ns {
            return Err(ClockError::MonotonicBackwards);
        }
        let elapsed_ns = monotonic_ns
            .checked_sub(self.anchor_ns)
            .ok_or(ClockError::MonotonicBackwards)?;
        let unix_ns = self
            .anchor_unix_ns
            .checked_add(u128::from(elapsed_ns))
            .ok_or(ClockError::Overflow)?;
        let unix_us = narrow_u64(unix_ns / NS_PER_US)?;
        let uncertainty_us = self
            .anchor_uncertainty_ns
            .map(|ns| {
                let total_ns = ns
                    .checked_add(unix_ns % NS_PER_US)
                    .ok_or(ClockError::Overflow)?;
                ceil_microseconds(total_ns)
            })
            .transpose()?;
        let snapshot = ClockSnapshot {
            monotonic_ns,
            unix_us,
            resolution_ns: self.resolution_ns,
            uncertainty_us,
            source: self.source_label.clone(),
        };
        // Failed source reads, reversals, and conversion errors cannot reset
        // the accepted sample or require a new wall anchor.
        state.last_ns = monotonic_ns;
        Ok(snapshot)
    }
}

/// Subtract same-origin monotonic ns before narrowing the duration to `u64` ns.
///
/// # Errors
/// Returns [`ClockError::MonotonicBackwards`] for reversal or
/// [`ClockError::Overflow`] if the difference does not fit `u64`.
pub fn duration_ns(start_ns: u128, end_ns: u128) -> Result<u64, ClockError> {
    narrow_u64(checked_interval(start_ns, end_ns)?)
}

/// Subtract same-origin monotonic ns, divide by 1,000, then narrow to `u64` us.
///
/// Inputs need not fit `u64`; only the microsecond result must. Sub-us portions
/// are truncated; retain [`duration_ns`] when those portions matter.
///
/// # Errors
/// Returns [`ClockError::MonotonicBackwards`] for reversal or
/// [`ClockError::Overflow`] if the microsecond difference does not fit `u64`.
pub fn duration_us(start_ns: u128, end_ns: u128) -> Result<u64, ClockError> {
    narrow_u64(checked_interval(start_ns, end_ns)? / NS_PER_US)
}

fn checked_interval(start_ns: u128, end_ns: u128) -> Result<u128, ClockError> {
    end_ns
        .checked_sub(start_ns)
        .ok_or(ClockError::MonotonicBackwards)
}

fn narrow_u64(value: u128) -> Result<u64, ClockError> {
    u64::try_from(value).map_err(|_| ClockError::Overflow)
}

fn ceil_microseconds(ns: u128) -> Result<u64, ClockError> {
    // Avoid ns + 999, which can overflow before division on untrusted input.
    let us = (ns / NS_PER_US)
        .checked_add(u128::from(!ns.is_multiple_of(NS_PER_US)))
        .ok_or(ClockError::Overflow)?;
    narrow_u64(us)
}

#[cfg(test)]
mod anchor_tests;
#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod test_support;
