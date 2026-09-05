use std::collections::VecDeque;

use super::{Clock, ClockError, ClockSource, WallClockSample};

pub(super) const EPOCH_US: u64 = 1_788_480_000_123_456;
pub(super) const EPOCH_NS: u128 = 1_788_480_000_123_456_000;

pub(super) fn wall(unix_ns: u128) -> WallClockSample {
    WallClockSample {
        unix_ns,
        resolution_ns: 1,
        uncertainty_ns: Some(0),
    }
}

pub(super) enum Reading {
    Monotonic(Result<u128, ClockError>),
    Wall(Result<WallClockSample, ClockError>),
}

// Ordered OS-boundary input: extra reads or wall reads outside the bracket fail.
pub(super) struct ScriptedSource {
    pub(super) readings: VecDeque<Reading>,
    pub(super) label: String,
}

impl ScriptedSource {
    pub(super) fn new(samples: &[u128], wall: WallClockSample) -> Self {
        let mut readings = VecDeque::new();
        for (index, sample) in samples.iter().enumerate() {
            if index == 1 {
                readings.push_back(Reading::Wall(Ok(wall)));
            }
            readings.push_back(Reading::Monotonic(Ok(*sample)));
        }
        Self {
            readings,
            label: "injected exact clock".into(),
        }
    }
}

impl ClockSource for ScriptedSource {
    fn source(&self) -> &str {
        &self.label
    }

    fn monotonic_now_ns(&mut self) -> Result<u128, ClockError> {
        match self.readings.pop_front() {
            Some(Reading::Monotonic(value)) => value,
            _ => Err(ClockError::SourceUnavailable),
        }
    }

    fn wall_now(&mut self) -> Result<WallClockSample, ClockError> {
        match self.readings.pop_front() {
            Some(Reading::Wall(value)) => value,
            _ => Err(ClockError::SourceUnavailable),
        }
    }
}

pub(super) fn clock(
    samples: &[u128],
    wall: WallClockSample,
) -> Result<Clock<ScriptedSource>, ClockError> {
    let result = Clock::with_source(ScriptedSource::new(samples, wall));
    assert!(
        result.is_ok(),
        "valid anchor rejected: {:?}",
        result.as_ref().err()
    );
    result
}
