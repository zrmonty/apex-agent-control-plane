use std::cell::Cell;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use super::test_support::{EPOCH_NS, wall};
use super::{Clock, ClockError, ClockSource, WallClockSample};

// Cell makes this source Send but not Sync. Clock must own and serialize it.
struct CounterSource {
    next: Cell<u128>,
    wall: Arc<Mutex<WallClockSample>>,
    panic_at: Option<u128>,
}

impl ClockSource for CounterSource {
    fn source(&self) -> &str {
        "injected serial counter"
    }

    fn monotonic_now_ns(&mut self) -> Result<u128, ClockError> {
        let sample = self.next.get();
        // Deliberate test-only unwind exercises the clock's poisoned-state path.
        assert_ne!(self.panic_at, Some(sample), "injected source panic");
        self.next
            .set(sample.checked_add(1_000).ok_or(ClockError::Overflow)?);
        thread::yield_now();
        Ok(sample)
    }

    fn wall_now(&mut self) -> Result<WallClockSample, ClockError> {
        self.wall
            .lock()
            .map(|sample| *sample)
            .map_err(|_| ClockError::Poisoned)
    }
}

#[test]
fn wall_jumps_and_metadata_changes_never_reanchor_existing_clock() -> Result<(), ClockError> {
    let wall_state = Arc::new(Mutex::new(wall(EPOCH_NS)));
    let clock = Clock::with_source(CounterSource {
        next: Cell::new(0),
        wall: Arc::clone(&wall_state),
        panic_at: None,
    })?;
    let initial = clock.now()?;
    assert_eq!(initial.unix_us, 1_788_480_000_123_457);
    *wall_state.lock().map_err(|_| ClockError::Poisoned)? = WallClockSample {
        unix_ns: 1_788_479_940_123_456_000,
        resolution_ns: 1_000_000,
        uncertainty_ns: None,
    };
    let backwards_wall = clock.now()?;
    assert_eq!(backwards_wall.unix_us, 1_788_480_000_123_458);
    *wall_state.lock().map_err(|_| ClockError::Poisoned)? = wall(1_788_480_060_123_456_000);
    let forwards_wall = clock.now()?;
    assert_eq!(forwards_wall.unix_us, 1_788_480_000_123_459);
    for snapshot in [backwards_wall, forwards_wall] {
        assert_eq!(snapshot.resolution_ns, initial.resolution_ns);
        assert_eq!(snapshot.uncertainty_us, initial.uncertainty_us);
        assert_eq!(snapshot.source, initial.source);
    }
    Ok(())
}

#[test]
fn concurrent_sampling_has_no_false_reversal_duplicate_or_lost_sample() -> Result<(), ClockError> {
    let clock = Clock::with_source(CounterSource {
        next: Cell::new(0),
        wall: Arc::new(Mutex::new(wall(EPOCH_NS))),
        panic_at: None,
    })?;
    let barrier = Barrier::new(8);
    let snapshots = thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    (0..32).map(|_| clock.now()).collect::<Result<Vec<_>, _>>()
                })
            })
            .collect();
        let mut all = Vec::new();
        for handle in handles {
            let joined = handle.join();
            assert!(joined.is_ok(), "clock sampling panicked");
            let samples = joined.map_err(|_| ClockError::Poisoned)??;
            for pair in samples.windows(2) {
                assert!(pair[0].monotonic_ns < pair[1].monotonic_ns);
            }
            all.extend(samples);
        }
        Ok::<_, ClockError>(all)
    })?;
    // Return order across threads is unspecified; source acquisition is ordered.
    let mut monotonic: Vec<_> = snapshots.iter().map(|s| s.monotonic_ns).collect();
    monotonic.sort_unstable();
    assert_eq!(
        monotonic,
        (2_000..=257_000).step_by(1_000).collect::<Vec<u64>>()
    );
    let mut epochs: Vec<_> = snapshots.iter().map(|s| s.unix_us).collect();
    epochs.sort_unstable();
    assert_eq!(
        epochs,
        (1_788_480_000_123_457..=1_788_480_000_123_712).collect::<Vec<u64>>()
    );
    Ok(())
}

#[test]
fn source_unwind_leaves_an_explicit_poison_error() -> Result<(), ClockError> {
    let clock = Clock::with_source(CounterSource {
        next: Cell::new(0),
        wall: Arc::new(Mutex::new(wall(EPOCH_NS))),
        panic_at: Some(2_000),
    })?;
    let joined = thread::scope(|scope| scope.spawn(|| clock.now()).join());
    assert!(joined.is_err(), "the injected source should have unwound");
    assert_eq!(clock.now(), Err(ClockError::Poisoned));
    Ok(())
}
