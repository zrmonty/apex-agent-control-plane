//! Component-only scheduling tests using a !Send probe, not PostgreSQL evidence.

use super::{BrowserError, component_support::*};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[test]
fn component_construct_use_and_drop_stay_on_one_named_non_tokio_thread() {
    let (worker, witness) = component_worker();
    let used = runtime().block_on(async move {
        worker
            .request(|_| Ok(ThreadRecord::current()))
            .await
            .unwrap()
    });
    let dropped = witness.wait_for_drop();
    assert_eq!(used.id, dropped.id);
    assert_eq!(used.name.as_deref(), Some("apex-browser-sessions"));
    assert!(!used.in_tokio);
}

#[test]
fn component_admission_allows_eight_queued_jobs_and_refuses_the_ninth_promptly() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        let mut queued = Vec::new();
        for _ in 0..8 {
            let mut request = Box::pin(worker.request(Probe::mutate));
            poll_pending(request.as_mut()).await;
            queued.push(request);
        }
        let result =
            tokio::time::timeout(Duration::from_millis(100), worker.request(Probe::mutate))
                .await
                .expect("full admission must not wait for capacity");
        assert_eq!(result, Err(BrowserError::RateLimited));
        drop(queued);
        release.release();
        let _ = busy.await.unwrap();
        worker.request(Probe::mutations).await.unwrap();
    });
    witness.wait_for_drop();
}

#[test]
fn component_a_never_polled_request_does_not_mutate() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        drop(worker.request(Probe::mutate));
        assert_eq!(worker.request(Probe::mutations).await.unwrap(), 0);
    });
    witness.wait_for_drop();
}

#[test]
fn component_cancelled_queued_request_is_discarded_before_mutation() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        let mut queued = Box::pin(worker.request(Probe::mutate));
        poll_pending(queued.as_mut()).await;
        drop(queued);
        release.release();
        let _ = busy.await.unwrap();
        // FIFO read observes the backend after it has dealt with the cancelled job.
        assert_eq!(worker.request(Probe::mutations).await.unwrap(), 0);
    });
    witness.wait_for_drop();
}

#[test]
fn component_expired_queued_reply_is_skipped_even_if_its_future_is_not_repolled() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        let mut queued = Box::pin(worker.request(Probe::mutate));
        poll_pending(queued.as_mut()).await;
        // Real monotonic time is shared with the standard worker thread. Do not
        // advance only Tokio's clock or poll the queued future to close its reply.
        tokio::time::sleep(Duration::from_millis(5_100)).await;
        release.release();
        let _ = busy.await.unwrap();
        assert_eq!(worker.request(Probe::mutations).await.unwrap(), 0);
        assert_eq!(queued.await, Err(BrowserError::Unavailable));
    });
    witness.wait_for_drop();
}

#[test]
fn component_request_deadline_includes_queue_wait_and_running_backend_time() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release_first) = stall(worker.clone()).await;
        let (release_second, second_gate) = gate();
        let (entered, started) = oneshot::channel();
        let mut queued = Box::pin(worker.request(move |_| {
            let _ = entered.send(());
            wait_at_gate(second_gate)
        }));
        let requested_at = Instant::now();
        poll_pending(queued.as_mut()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        release_first.release();
        let _ = busy.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), started)
            .await
            .unwrap()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(3_500), queued)
            .await
            .expect("the queue wait must consume the five-second request budget");
        assert_eq!(result, Err(BrowserError::Unavailable));
        assert!(requested_at.elapsed() < Duration::from_millis(5_750));
        release_second.release();
        worker.request(Probe::mutations).await.unwrap();
    });
    witness.wait_for_drop();
}

#[test]
fn component_aborting_an_in_flight_mutation_never_replays_it() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (release, receiver) = gate();
        let (entered, started) = oneshot::channel();
        let caller = worker.clone();
        let task = tokio::spawn(async move {
            caller
                .request(move |probe| {
                    probe.mutate()?;
                    let _ = entered.send(());
                    wait_at_gate(receiver)
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.release();
        assert_eq!(worker.request(Probe::mutations).await.unwrap(), 1);
        assert_eq!(worker.request(Probe::mutate).await.unwrap(), 2);
    });
    witness.wait_for_drop();
}

#[test]
fn component_closed_reply_receiver_is_a_redacted_unavailable_error() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let error = worker
            .request::<()>(|_| panic!("component worker exit"))
            .await
            .expect_err("worker exit must close the reply");
        assert_eq!(error, BrowserError::Unavailable);
        assert_eq!(error.to_string(), "unavailable");
        assert_eq!(format!("{error:?}"), "Unavailable");
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(
            worker.request(Probe::mutations).await,
            Err(BrowserError::Unavailable)
        );
    });
    witness.wait_for_drop();
}
