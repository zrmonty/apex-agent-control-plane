//! Component-only lifecycle tests. PostgreSQL lifecycle has separate integration tests.

use super::{BrowserError, Worker, component_support::*};
use std::time::{Duration, Instant};

#[test]
fn component_dropping_a_parent_future_before_first_poll_releases_its_owner() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let never_polled = async move { worker.request(Probe::mutate).await };
        drop(never_polled);
    });
    witness.wait_for_drop();
}

#[test]
fn component_aborting_before_first_poll_releases_its_owner() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        // On this current-thread runtime spawn cannot poll before we yield.
        let task = tokio::spawn(async move { worker.request(Probe::mutate).await });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    });
    witness.wait_for_drop();
}

#[test]
fn component_last_drop_while_backend_stalls_does_not_join_on_tokio() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        busy.abort();
        assert!(busy.await.unwrap_err().is_cancelled());
        let dropped_at = Instant::now();
        drop(worker);
        assert!(dropped_at.elapsed() < Duration::from_millis(100));
        // Keep the backend blocked until a runtime timer has made progress. A
        // join in Drop would wait for the fixture's 12-second safety timeout.
        tokio::time::sleep(Duration::from_millis(20)).await;
        release.release();
    });
    witness.wait_for_drop();
}

#[test]
fn component_shutdown_stops_all_clones_and_is_idempotent() {
    let (worker, witness) = component_worker();
    let clone = worker.clone();
    let runtime = runtime();
    runtime.block_on(async {
        worker
            .shutdown()
            .await
            .expect("explicit shutdown must report completed cleanup");
    });
    // Completion must mean owner destruction, even while both facades survive.
    witness.wait_for_drop();
    runtime.block_on(async {
        assert_eq!(
            worker.request(Probe::mutate).await,
            Err(BrowserError::Unavailable)
        );
        assert_eq!(
            clone.request(Probe::mutate).await,
            Err(BrowserError::Unavailable)
        );
        clone.shutdown().await.unwrap();
        worker.shutdown().await.unwrap();
    });
}

#[test]
fn component_shutdown_refuses_new_admission_and_discards_already_queued_commands() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        let mut queued = Box::pin(worker.request(Probe::mutate));
        poll_pending(queued.as_mut()).await;
        let mut shutdown = Box::pin(worker.shutdown());
        poll_pending(shutdown.as_mut()).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), worker.request(Probe::mutate))
                .await
                .expect("shutdown must refuse new work promptly"),
            Err(BrowserError::Unavailable)
        );
        release.release();
        let _ = busy.await.unwrap();
        shutdown.await.unwrap();
        assert_eq!(queued.await, Err(BrowserError::Unavailable));
    });
    witness.wait_for_drop();
    witness.assert_mutations(0);
}

#[test]
fn component_cancelling_shutdown_does_not_reopen_admission_or_keep_the_owner_alive() {
    let (worker, witness) = component_worker();
    let runtime = runtime();
    runtime.block_on(async {
        let (busy, release) = stall(worker.clone()).await;
        let mut shutdown = Box::pin(worker.shutdown());
        poll_pending(shutdown.as_mut()).await;
        drop(shutdown);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), worker.request(Probe::mutate))
                .await
                .expect("cancelled shutdown must retain its stop decision"),
            Err(BrowserError::Unavailable)
        );
        release.release();
        let _ = busy.await.unwrap();
    });
    // The original facade is deliberately still alive at this observation.
    witness.wait_for_drop();
    drop(worker);
}

#[test]
fn component_shutdown_wait_has_a_deadline_even_when_the_backend_cannot_finish_yet() {
    let (worker, witness) = component_worker();
    runtime().block_on(async move {
        let (busy, release) = stall(worker.clone()).await;
        let requested_at = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(6), worker.shutdown())
            .await
            .expect("shutdown wait must be bounded");
        assert_eq!(result, Err(BrowserError::Unavailable));
        assert!(
            requested_at.elapsed() >= Duration::from_secs(4),
            "must await cleanup until its deadline"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), worker.request(Probe::mutate))
                .await
                .unwrap(),
            Err(BrowserError::Unavailable)
        );
        release.release();
        let _ = busy.await.unwrap();
    });
    witness.wait_for_drop();
}

#[test]
fn component_startup_deadline_covers_the_entire_factory_and_late_owner_is_dropped() {
    let (factory, witness) = component_factory();
    let (release, receiver) = gate();
    let started_at = Instant::now();
    // The first phase constructs an owner. The second represents initialization
    // still running before readiness. This is a component test, not a PG migration.
    let result = Worker::start(move || {
        let owner = factory()?;
        wait_at_gate(receiver)?;
        Ok(owner)
    });
    assert!(matches!(result, Err(BrowserError::Unavailable)));
    assert!(started_at.elapsed() >= Duration::from_secs(4));
    assert!(started_at.elapsed() < Duration::from_secs(6));
    release.release();
    witness.wait_for_drop();
}

#[test]
fn component_shutdown_rejects_buffered_completion_after_original_deadline() {
    let (worker, witness) = component_worker();
    let clone = worker.clone();
    runtime().block_on(async {
        let (busy, release) = stall(worker.clone()).await;
        let mut done = worker.owner.done.clone();
        let mut original = Box::pin(worker.shutdown());
        poll_pending(original.as_mut()).await;
        // Retain the future without polling its timeout. Cleanup is deliberately
        // blocked until AFTER its real five-second budget, then separately observed.
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert!(!*done.borrow());
        release.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let complete = *done.borrow_and_update();
                if complete { break; }
                done.changed().await.unwrap();
            }
        }).await.expect("released worker must complete cleanup");
        assert_eq!(original.await, Err(BrowserError::Unavailable));
        assert_eq!(clone.request(Probe::mutate).await, Err(BrowserError::Unavailable));
        worker.shutdown().await.unwrap();
        clone.shutdown().await.unwrap();
        let _ = busy.await.unwrap();
    });
    witness.wait_for_drop();
    witness.assert_mutations(0);
}
