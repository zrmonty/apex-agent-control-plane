//! Direct private queue/oneshot checks, explicitly not successful PG/TLS evidence.

use super::super::{executor, lifecycle::Shared};
use super::executor_support::*;
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

fn queue() -> (
    executor::Client<ThreadRecord>,
    std::sync::mpsc::Receiver<executor::Job<ThreadRecord>>,
    Arc<Shared>,
) {
    let shared = Arc::new(Shared::new());
    publish(&shared, "enrollment-1");
    let (client, receiver) = executor::channel(Arc::clone(&shared));
    (client, receiver, shared)
}

#[test]
fn component_cancel_guard_exists_at_enqueue_and_drop_cancels_even_without_timer_poll() {
    let (client, receiver, shared) = queue();
    runtime().block_on(async {
        let mut pending = Box::pin(client.request(lookup(&shared, OBSERVE)));
        poll_pending(pending.as_mut()).await;
        let job = receiver.recv_timeout(OBSERVE).unwrap();
        assert!(!job.cancelled.load(Ordering::Acquire));
        assert!(
            job.check().is_ok(),
            "live queued request is a positive checkpoint control"
        );
        drop(pending);
        assert!(
            job.cancelled.load(Ordering::Acquire),
            "drop guard must be installed before enqueue"
        );
        assert_eq!(
            job.check().unwrap_err().code(),
            "RUNTIME_AUTHORITY_CANCELLED"
        );
    });
}

#[test]
fn component_buffered_result_delivered_after_budget_never_becomes_late_success() {
    let (client, receiver, shared) = queue();
    runtime().block_on(async {
        // First prove that this same typed channel can deliver a timely result.
        let mut control = Box::pin(client.request(lookup(&shared, OBSERVE)));
        poll_pending(control.as_mut()).await;
        receiver
            .recv_timeout(OBSERVE)
            .unwrap()
            .reply
            .send(Ok(ThreadRecord::current()))
            .unwrap();
        control.await.unwrap();

        let mut late = Box::pin(client.request(lookup(&shared, Duration::from_millis(50))));
        poll_pending(late.as_mut()).await;
        receiver
            .recv_timeout(OBSERVE)
            .unwrap()
            .reply
            .send(Ok(ThreadRecord::current()))
            .unwrap();
        // Result is buffered; do not poll this request's timer until it is late.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_status(
            late.await,
            tonic::Code::DeadlineExceeded,
            "RUNTIME_AUTHORITY_DEADLINE",
        );
    });
}

#[test]
fn component_deadline_starts_at_handler_entry_not_at_queue_submission() {
    let (client, receiver, shared) = queue();
    let mut expired = lookup(&shared, Duration::from_millis(50));
    expired.started = Instant::now() - Duration::from_secs(1);
    assert_status(
        runtime().block_on(client.request(expired)),
        tonic::Code::DeadlineExceeded,
        "RUNTIME_AUTHORITY_DEADLINE",
    );
    assert!(
        receiver.try_recv().is_err(),
        "already-expired claims never enter the queue"
    );
}

#[test]
fn component_zero_budget_and_future_monotonic_entry_refuse_before_queue() {
    let (client, receiver, shared) = queue();
    let mut future = lookup(&shared, OBSERVE);
    future.started = Instant::now() + Duration::from_secs(1);
    for invalid in [lookup(&shared, Duration::ZERO), future] {
        assert_status(
            runtime().block_on(client.request(invalid)),
            tonic::Code::DeadlineExceeded,
            "RUNTIME_AUTHORITY_DEADLINE",
        );
        assert!(receiver.try_recv().is_err());
    }
}

#[test]
fn component_closed_reply_and_stopped_queue_emit_only_static_refusal() {
    let (client, receiver, shared) = queue();
    runtime().block_on(async {
        let mut pending = Box::pin(client.request(lookup(&shared, OBSERVE)));
        poll_pending(pending.as_mut()).await;
        drop(receiver.recv_timeout(OBSERVE).unwrap());
        assert_status(
            pending.await,
            tonic::Code::Unavailable,
            "RUNTIME_AUTHORITY_UNAVAILABLE",
        );
        let next = lookup(&shared, OBSERVE);
        shared.stop();
        assert_status(
            client.request(next).await,
            tonic::Code::Unavailable,
            "RUNTIME_AUTHORITY_UNAVAILABLE",
        );
    });
}

#[test]
fn component_buffered_result_rechecks_generation_at_async_handoff() {
    let (client, receiver, shared) = queue();
    runtime().block_on(async {
        let mut pending = Box::pin(client.request(lookup(&shared, OBSERVE)));
        poll_pending(pending.as_mut()).await;
        receiver
            .recv_timeout(OBSERVE)
            .unwrap()
            .reply
            .send(Ok(ThreadRecord::current()))
            .unwrap();
        publish(&shared, "enrollment-2");
        assert_status(
            pending.await,
            tonic::Code::FailedPrecondition,
            "RUNTIME_AUTHORITY_POLICY_CHANGED",
        );
    });
}
