//! Component-only typed scheduling tests; not real PG/TLS callback acceptance.

use super::executor_support::*;
use std::time::Duration;

#[test]
fn component_backend_construct_use_drop_share_one_named_thread_outside_tokio() {
    let mut running = Running::start();
    let created = running.witness.created.recv_timeout(OBSERVE).unwrap();
    let step = running.witness.step(None);
    let used = runtime()
        .block_on(running.client.request(running.lookup(OBSERVE)))
        .unwrap();
    assert_eq!(step.entered.recv_timeout(OBSERVE).unwrap(), used);
    assert_eq!(used, created);
    assert_eq!(used.name.as_deref(), Some("apex-runtime-authority"));
    assert!(!used.in_tokio);
    assert!(running.owner.shutdown(OBSERVE).cleanup_complete);
    assert_eq!(
        running.witness.dropped.recv_timeout(OBSERVE).unwrap(),
        created
    );
}

#[test]
fn component_eight_queued_jobs_refuse_ninth_immediately_then_healthy_request_runs() {
    let running = Running::start();
    let (release, gate) = gate();
    let stalled = running.witness.step(Some(gate));
    runtime().block_on(async {
        let mut busy = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(busy.as_mut()).await;
        stalled.entered.recv_timeout(OBSERVE).unwrap();
        let mut queued = Vec::new();
        for _ in 0..8 {
            let mut job = Box::pin(running.client.request(running.lookup(OBSERVE)));
            poll_pending(job.as_mut()).await;
            queued.push(job);
        }
        let ninth = tokio::time::timeout(
            Duration::from_millis(100),
            running.client.request(running.lookup(OBSERVE)),
        )
        .await
        .expect("queue-full is immediate");
        assert_status(
            ninth,
            tonic::Code::ResourceExhausted,
            "RUNTIME_AUTHORITY_BUSY",
        );
        drop(queued);
        release.release();
        busy.await.unwrap();
        let next = running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
        next.after_checkpoint.recv_timeout(OBSERVE).unwrap();
    });
}

#[test]
fn component_dropped_queued_future_never_dispatches_before_next_explicit_request() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.step(Some(gate));
    runtime().block_on(async {
        let mut busy = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(busy.as_mut()).await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        let mut cancelled = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(cancelled.as_mut()).await;
        drop(cancelled);
        release.release();
        busy.await.unwrap();
        // Only the healthy request has a backend step. A cancelled dispatch
        // consumes it incorrectly and makes this positive control fail.
        running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
    });
}

#[test]
fn component_expired_queued_future_is_skipped_without_repolling_its_timer() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.step(Some(gate));
    runtime().block_on(async {
        let mut busy = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(busy.as_mut()).await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        let mut expired = Box::pin(
            running
                .client
                .request(running.lookup(Duration::from_millis(50))),
        );
        poll_pending(expired.as_mut()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        release.release();
        busy.await.unwrap();
        running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
        assert_status(
            expired.await,
            tonic::Code::DeadlineExceeded,
            "RUNTIME_AUTHORITY_DEADLINE",
        );
    });
}

#[test]
fn component_abort_during_backend_prevents_next_checkpoint_and_serializes_cleanup() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.step(Some(gate));
    runtime().block_on(async {
        let client = running.client.clone();
        let lookup = running.lookup(OBSERVE);
        let task = tokio::spawn(async move { client.request(lookup).await });
        // Explicitly yield the current-thread runtime so the caller can enqueue.
        tokio::task::yield_now().await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let next = running.witness.step(None);
        let mut healthy = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(healthy.as_mut()).await;
        assert!(
            next.entered
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "no next backend call while the previous read still owns cleanup"
        );
        release.release();
        healthy.await.unwrap();
        assert!(
            first.after_checkpoint.recv_timeout(OBSERVE).is_err(),
            "the aborted read cannot start its next query checkpoint"
        );
        next.after_checkpoint.recv_timeout(OBSERVE).unwrap();
    });
}

#[test]
fn component_policy_replacement_while_backend_waits_refuses_then_new_request_recovers() {
    let running = Running::start();
    let (release, gate) = gate();
    let first = running.witness.step(Some(gate));
    runtime().block_on(async {
        let mut old = Box::pin(running.client.request(running.lookup(OBSERVE)));
        poll_pending(old.as_mut()).await;
        first.entered.recv_timeout(OBSERVE).unwrap();
        // No policy mutex may be held by the blocked backend.
        assert!(running.owner.shared.policy.try_lock().is_ok());
        publish(&running.owner.shared, "enrollment-2");
        release.release();
        assert_status(
            old.await,
            tonic::Code::FailedPrecondition,
            "RUNTIME_AUTHORITY_POLICY_CHANGED",
        );
        assert!(first.after_checkpoint.recv_timeout(OBSERVE).is_err());
        running.witness.step(None);
        running
            .client
            .request(running.lookup(OBSERVE))
            .await
            .unwrap();
    });
}
