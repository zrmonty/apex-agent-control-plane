use super::super::{RuntimeExecutionClient, RuntimeExecutionConfig, unavailable};
use crate::proto;
use std::time::{Duration, Instant};
mod adversarial;
mod fixture;
mod lifetime;
#[allow(dead_code, clippy::duplicate_mod)]
#[path = "../../../../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
mod preflight;
mod protected;
use fixture::*;

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_preserves_original_launch_and_integers_with_fresh_nonce_per_call() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Good);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let config = fixture.config(&pki, pki::CONTROLLER);
        let mut client = RuntimeExecutionClient::connect(&config, deadline())
            .await
            .unwrap();
        let (request, observed) = inputs();
        for _ in 0..2 {
            let observation = client
                .observe_health(&request, &observed, deadline(), &|| Ok(()))
                .await
                .unwrap();
            assert_eq!(
                format!("{observation:?}"),
                "HealthObservation { [redacted; data only] }"
            );
            let (report, remaining) = observation.into_remaining().unwrap();
            assert_eq!(report, fixture.report);
            assert_eq!(report.stages[0].duration_ns, Some(9_007_199_254_740_993));
            assert_eq!(report.target.unwrap().fencing_token, 9_007_199_254_740_993);
            assert!(remaining > Duration::ZERO && remaining < Duration::from_secs(10));
        }
    });
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].nonce.len(), 32);
    assert_ne!(requests[0].nonce, requests[1].nonce);
    let (_, observed) = inputs();
    assert_eq!(
        requests[0].binding.as_ref().unwrap().target,
        observed.runtime.unwrap().target
    );
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_preserves_full_uint64_timing_and_optional_presence_with_bounded_timeout() {
    fn change(reply: &mut proto::RuntimeHealthObservationResponse) {
        let report = reply.sample.as_mut().unwrap().report.as_mut().unwrap();
        report.observed_at_unix_us = u64::MAX;
        report.checks.reverse();
        for (stage, ns) in report.stages.iter_mut().zip([
            0,
            1,
            999,
            1000,
            1001,
            9_007_199_254_740_993,
            u64::MAX,
            7,
            11,
        ]) {
            stage.started_at_unix_us = u64::MAX;
            stage.duration_ns = Some(ns);
            stage.duration_us = ns / 1000;
            stage.clock_resolution_ns = u64::MAX;
            stage.clock_uncertainty_us = Some(u64::MAX);
        }
        report.stages[0].clock_uncertainty_us = None;
        report.stages[1].clock_uncertainty_us = Some(0);
    }
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Mutate(change));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client =
            RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                .await
                .unwrap();
        let (request, observed) = inputs();
        let health = client
            .observe_health(
                &request,
                &observed,
                Instant::now() + Duration::from_secs(60),
                &|| Ok(()),
            )
            .await
            .unwrap();
        let (report, remaining) = health.into_remaining().unwrap();
        assert_eq!(report.observed_at_unix_us, u64::MAX);
        assert_eq!(report.stages[0].duration_ns, Some(0));
        assert_eq!(report.stages[1].duration_ns, Some(1));
        assert_eq!(report.stages[2].duration_ns, Some(999));
        assert_eq!(report.stages[6].duration_ns, Some(u64::MAX));
        assert_eq!(report.stages[6].duration_us, 18_446_744_073_709_551);
        assert_eq!(report.stages[0].clock_uncertainty_us, None);
        assert_eq!(report.stages[1].clock_uncertainty_us, Some(0));
        assert_eq!(report.stages[2].clock_uncertainty_us, Some(u64::MAX));
        assert!(remaining < Duration::from_secs(10));
    });
}
