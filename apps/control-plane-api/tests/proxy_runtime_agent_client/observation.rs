//! Test-only observation of read-only authority calls across a refresh tick.
use serde_json::Value;
use std::time::{Duration, Instant};

pub(super) fn after_refresh(attempt: impl FnMut(Instant) -> Value) -> Value {
    observe_until(Instant::now() + Duration::from_secs(15), attempt)
}

fn observe_until(deadline: Instant, mut attempt: impl FnMut(Instant) -> Value) -> Value {
    for number in 1..=3 {
        assert!(
            Instant::now() < deadline,
            "authority observation watchdog expired"
        );
        let result = attempt(deadline);
        assert!(
            Instant::now() < deadline,
            "authority observation watchdog expired"
        );
        if number == 3
            || result.get("snapshot").is_some()
            || result.get("error").and_then(Value::as_str)
                != Some("RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE")
        {
            // The caller still checks the exact snapshot or refusal. Exhausted
            // unavailability is returned as failure evidence, never success.
            return result;
        }
        eprintln!("authority_test_observation_retry attempt={number}");
        std::thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    unreachable!("the final attempt always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transient_unavailability_requires_a_subsequent_specific_result() {
        let mut replies = [
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE"}),
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL"}),
        ]
        .into_iter();
        let result = after_refresh(|_| replies.next().expect("no extra attempts"));
        assert_eq!(
            result,
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL"})
        );
    }

    #[test]
    fn persistent_unavailability_is_returned_after_three_attempts_not_accepted() {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut calls = 0;
        let result = observe_until(deadline, |until| {
            assert_eq!(until, deadline, "retries never extend the watchdog");
            calls += 1;
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE"})
        });
        assert_eq!(calls, 3);
        assert_eq!(
            result,
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE"})
        );
    }

    #[test]
    fn denial_timeout_wrong_refusal_and_snapshot_are_never_retried() {
        for result in [
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_DENIED"}),
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_DEADLINE"}),
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_TRANSPORT"}),
            json!({"error":"RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL"}),
            json!({"snapshot":{}}),
            json!({"snapshot":{},"error":"RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE"}),
        ] {
            let mut calls = 0;
            assert_eq!(
                after_refresh(|_| {
                    calls += 1;
                    result.clone()
                }),
                result
            );
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn expired_watchdog_refuses_before_launching_any_attempt() {
        let mut calls = 0;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observe_until(Instant::now() - Duration::from_secs(1), |_| {
                calls += 1;
                json!({"snapshot":{}})
            })
        }));
        assert!(result.is_err(), "expired observation must fail");
        assert_eq!(calls, 0);
    }
}
