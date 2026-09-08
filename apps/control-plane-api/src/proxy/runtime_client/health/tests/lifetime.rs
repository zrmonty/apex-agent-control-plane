use super::*;
use std::sync::atomic::Ordering;

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_held_rpc_obeys_original_deadline_and_cancellation() {
    let pki = pki::Pki::require();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for cancelled in [false, true] {
        let fixture = Fixture::new(&pki, Mode::Hold);
        runtime.block_on(async {
            let mut client =
                RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                    .await
                    .unwrap();
            let (request, observed) = inputs();
            let start = Instant::now();
            let original_deadline = if cancelled {
                deadline()
            } else {
                start + Duration::from_millis(150)
            };
            let check = || {
                if cancelled && !fixture.requests.lock().unwrap().is_empty() {
                    Err(unavailable())
                } else {
                    Ok(())
                }
            };
            assert!(
                client
                    .observe_health(&request, &observed, original_deadline, &check)
                    .await
                    .is_err()
            );
            assert!(start.elapsed() < Duration::from_millis(750));
            assert_eq!(fixture.requests.lock().unwrap().len(), 1);
            // Reusing an expired deadline or cancelled checkpoint cannot dispatch.
            assert!(
                client
                    .observe_health(&request, &observed, original_deadline, &check)
                    .await
                    .is_err()
            );
            assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        });
    }
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_refuses_pre_dispatch_cancellation_and_post_response_replacement() {
    let pki = pki::Pki::require();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for initially_current in [false, true] {
        let fixture = Fixture::new(&pki, Mode::PostCurrent);
        fixture.current.store(initially_current, Ordering::SeqCst);
        runtime.block_on(async {
            let mut client =
                RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                    .await
                    .unwrap();
            let (request, observed) = inputs();
            let check = || {
                if fixture.current.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(unavailable())
                }
            };
            assert!(
                client
                    .observe_health(&request, &observed, deadline(), &check)
                    .await
                    .is_err()
            );
        });
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            usize::from(initially_current)
        );
    }
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_sample_loses_rpc_time_and_expires_before_later_handoff() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::DelayedSample);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client =
            RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                .await
                .unwrap();
        let (request, observed) = inputs();
        let health = client
            .observe_health(&request, &observed, deadline(), &|| Ok(()))
            .await
            .unwrap();
        let (report, remaining) = health.into_remaining().unwrap();
        assert_eq!(report, fixture.report);
        assert!(remaining < Duration::from_nanos(160_000_999));
        assert!(!remaining.is_zero());
        let health = client
            .observe_health(&request, &observed, deadline(), &|| Ok(()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(210)).await;
        assert!(
            health.into_remaining().is_err(),
            "handoff cannot renew freshness"
        );
    });
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_peer_status_details_are_redacted_without_retry_classification() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Status);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client =
            RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                .await
                .unwrap();
        let (request, observed) = inputs();
        let error = client
            .observe_health(&request, &observed, deadline(), &|| Ok(()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "RUNTIME_EXECUTION_UNAVAILABLE");
        assert!(!format!("{error:?} {error}").contains("CANARY"));
    });
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}
