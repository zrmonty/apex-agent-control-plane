//! Typed backend error results also require independent final checks.
//! Injected errors and synthetic metadata are not PostgreSQL/TLS acceptance.

use super::executor_support::*;
use std::time::Duration;

#[test]
fn component_policy_replacement_takes_precedence_after_backend_error() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.failing_step(Some(gate));
    runtime().block_on(async {
        let mut old = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(old.as_mut()).await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        publish(&running.owner.shared, "enrollment-2");
        release.release();
        assert_status(
            old.await,
            tonic::Code::FailedPrecondition,
            "RUNTIME_AUTHORITY_POLICY_CHANGED",
        );
        running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
    });
}

#[test]
fn component_expired_budget_takes_precedence_after_backend_error_and_recovers() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.failing_step(Some(gate));
    runtime().block_on(async {
        let mut old = Box::pin(
            running
                .client
                .request(running.lookup(Duration::from_millis(50))),
        );
        poll_pending(old.as_mut()).await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        release.release();
        assert_status(
            old.await,
            tonic::Code::DeadlineExceeded,
            "RUNTIME_AUTHORITY_DEADLINE",
        );
        running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
    });
}

#[test]
fn component_backend_error_message_never_crosses_the_reply_boundary() {
    let running = Running::start();
    running.witness.failing_step(None);
    let result = runtime().block_on(running.client.request(running.lookup(OBSERVE)));
    let error = result.expect_err("component transport failure");
    assert!(!format!("{error:?} {error}").contains("PRIVATE-QUERY-CANARY"));
    assert_status::<ThreadRecord>(
        Err(error),
        tonic::Code::Unavailable,
        "RUNTIME_AUTHORITY_UNAVAILABLE",
    );
    running.witness.step(None);
    runtime()
        .block_on(running.client.request(running.lookup(OBSERVE)))
        .unwrap();
}
