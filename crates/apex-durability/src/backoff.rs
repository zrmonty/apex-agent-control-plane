//! Bounded exponential backoff with jitter for the crate's in-process retry
//! loops (sink writes, JetStream publish). Every retry path here is currently
//! synchronous/blocking, so this sleeps the calling thread directly rather
//! than requiring an async runtime. Without jitter, a struggling sink gets
//! hammered at full speed by every attempt, and a fleet of gateway replicas
//! failing at the same moment retries in lockstep, worsening the exact
//! overload condition retries are meant to ride out.

use std::time::Duration;

const BASE_DELAY: Duration = Duration::from_millis(50);
const MAX_DELAY: Duration = Duration::from_secs(2);

/// Sleeps before a retry attempt. `attempt_index` is 0-based over prior
/// attempts (call with `0` before the 2nd attempt, `1` before the 3rd, ...;
/// never call before the 1st attempt). Delay grows exponentially from
/// `BASE_DELAY`, capped at `MAX_DELAY`, jittered to 50%-100% of the capped
/// value.
pub(crate) fn sleep_before_retry(attempt_index: usize) {
    std::thread::sleep(backoff_duration(attempt_index));
}

fn backoff_duration(attempt_index: usize) -> Duration {
    let exponent = attempt_index.min(6) as u32;
    let base = BASE_DELAY.saturating_mul(1u32.checked_shl(exponent).unwrap_or(u32::MAX));
    let capped = base.min(MAX_DELAY);
    capped.mul_f64(0.5 + 0.5 * random_unit_fraction())
}

fn random_unit_fraction() -> f64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Fail toward the full delay rather than a tight retry loop.
        return 1.0;
    }
    (u64::from_le_bytes(bytes) as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_stays_capped() {
        let first = backoff_duration(0);
        let later = backoff_duration(10);
        assert!(first >= BASE_DELAY.mul_f64(0.5));
        assert!(first <= BASE_DELAY);
        assert!(later <= MAX_DELAY);
        assert!(later >= MAX_DELAY.mul_f64(0.5));
    }
}
