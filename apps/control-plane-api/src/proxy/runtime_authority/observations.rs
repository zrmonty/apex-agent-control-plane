//! Bounded test-only scheduling witness; no request data or execution controls.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Default)]
pub(super) struct Counters {
    pub admitted: AtomicU64,
    pub visited: AtomicU64,
    pub dispatched: AtomicU64,
    pub settled: AtomicU64,
}

/// Read-only test-support counters. This cannot submit work or bypass authority.
#[derive(Clone)]
pub struct RuntimeAuthorityObservations(pub(super) Arc<Counters>);

impl RuntimeAuthorityObservations {
    /// Cumulative admitted, visited, dispatched and settled job counts.
    /// Counts are monotonic observations, not an atomic transaction snapshot.
    pub fn counts(&self) -> [u64; 4] {
        [
            &self.0.admitted,
            &self.0.visited,
            &self.0.dispatched,
            &self.0.settled,
        ]
        .map(|counter| counter.load(Ordering::Acquire))
    }
}
