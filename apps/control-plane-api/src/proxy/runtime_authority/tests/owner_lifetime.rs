//! Private owner lifecycle evidence only; real PostgreSQL is main-owned.

use super::super::RuntimeAuthorityError;
use super::executor_support::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[test]
fn component_final_facade_drop_before_first_poll_stops_without_explicit_owner_shutdown() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let client = owner
        .start(reader, factory, OBSERVE)
        .expect("component owner starts");
    let shared = Arc::clone(&owner.shared);
    let unused_lookup = lookup(&shared, OBSERVE);
    let never_polled = async move { client.request(unused_lookup).await };
    drop(never_polled);
    assert!(
        shared.stopped(),
        "last facade drop must signal synchronously"
    );
    witness
        .dropped
        .recv_timeout(OBSERVE)
        .expect("backend drops before owner.shutdown");
    let result = owner.shutdown(OBSERVE);
    assert!(result.reader_complete && result.postgres_complete && result.cleanup_complete);
    assert_eq!(owner.shutdown(OBSERVE), result);
}

#[test]
fn component_one_surviving_facade_keeps_admission_open_until_final_drop() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let client = owner.start(reader, factory, OBSERVE).unwrap();
    let retained = client.clone();
    drop(client);
    assert!(!owner.shared.stopped());
    witness.step(None);
    runtime()
        .block_on(retained.request(lookup(&owner.shared, OBSERVE)))
        .unwrap();
    drop(retained);
    witness.dropped.recv_timeout(OBSERVE).unwrap();
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
}

#[test]
fn component_shutdown_inside_tokio_signals_but_does_not_wait_or_claim_unjoined_handles() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let (release, gate) = gate();
    let client = owner
        .start(
            move |shared| reader_with(shared, None, Some(gate)),
            factory,
            OBSERVE,
        )
        .unwrap();
    let result = runtime().block_on(async {
        let before = Instant::now();
        let result = owner.shutdown(OBSERVE);
        assert!(before.elapsed() < Duration::from_millis(100));
        assert!(owner.shared.stopped());
        result
    });
    assert!(!result.reader_complete && !result.cleanup_complete);
    release.release();
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
    witness.dropped.recv_timeout(OBSERVE).unwrap();
    drop(client);
}

#[test]
fn component_timed_out_cleanup_retains_actual_handle_for_later_observation() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let (release, gate) = gate();
    let client = owner
        .start(
            move |shared| reader_with(shared, None, Some(gate)),
            factory,
            OBSERVE,
        )
        .unwrap();
    let result = owner.shutdown(Duration::from_millis(50));
    assert!(!result.reader_complete && !result.cleanup_complete);
    witness.dropped.recv_timeout(OBSERVE).unwrap();
    release.release();
    let completed = owner.shutdown(OBSERVE);
    assert!(completed.reader_complete && completed.postgres_complete && completed.cleanup_complete);
    assert_eq!(owner.shutdown(OBSERVE), completed);
    drop(client);
}

#[test]
fn component_failed_backend_start_retains_reader_and_never_invokes_a_replacement() {
    let mut owner = Owned::new();
    let failed = owner.start::<Probe>(reader, || Err(RuntimeAuthorityError::Unavailable), OBSERVE);
    assert!(matches!(failed, Err(RuntimeAuthorityError::Unavailable)));
    assert!(owner.shared.stopped());
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
    let retry = owner.start::<Probe>(
        |_| panic!("must not spawn replacement reader"),
        || panic!("must not construct replacement backend"),
        OBSERVE,
    );
    assert!(matches!(retry, Err(RuntimeAuthorityError::Unavailable)));
}

#[test]
fn component_start_in_entered_tokio_invokes_neither_factory_and_keeps_owner_observable() {
    let mut owner = Owned::new();
    let result = runtime().block_on(async {
        owner.start::<Probe>(
            |_| panic!("entered Tokio must not create reader"),
            || panic!("entered Tokio must not connect"),
            OBSERVE,
        )
    });
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
}

#[test]
fn component_startup_timeout_retains_late_backend_until_real_drop_and_join() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let (release, gate) = gate();
    let result = owner.start(
        reader,
        move || {
            let backend = factory()?;
            wait_gate(gate);
            Ok(backend)
        },
        Duration::from_millis(50),
    );
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    let created = witness.created.recv_timeout(OBSERVE).unwrap();
    assert!(owner.shared.stopped());
    assert!(!owner.shutdown(Duration::from_millis(25)).postgres_complete);
    release.release();
    assert_eq!(witness.dropped.recv_timeout(OBSERVE).unwrap(), created);
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
}

#[test]
fn component_shutdown_observes_two_blocked_threads_under_one_budget() {
    let (factory, witness) = backend();
    let mut owner = Owned::new();
    let (reader_release, reader_gate) = gate();
    let (backend_release, backend_gate) = gate();
    let client = owner
        .start(
            move |shared| reader_with(shared, None, Some(reader_gate)),
            factory,
            OBSERVE,
        )
        .unwrap();
    let step = witness.step(Some(backend_gate));
    let runtime = runtime();
    let mut pending = Box::pin(client.request(lookup(&owner.shared, OBSERVE)));
    runtime.block_on(poll_pending(pending.as_mut()));
    step.entered.recv_timeout(OBSERVE).unwrap();
    let before = Instant::now();
    let result = owner.shutdown(Duration::from_millis(400));
    let elapsed = before.elapsed();
    assert!(!result.reader_complete && !result.postgres_complete && !result.cleanup_complete);
    assert!(
        elapsed >= Duration::from_millis(350),
        "must observe the actual blocked owners"
    );
    assert!(
        elapsed < Duration::from_millis(700),
        "one observation budget, not one per thread"
    );
    reader_release.release();
    backend_release.release();
    drop(pending);
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
}

#[test]
fn component_initial_factory_time_consumes_the_single_startup_observation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (factory, _witness) = backend();
    let invoked = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&invoked);
    let mut owner = Owned::new();
    let before = Instant::now();
    let result = owner.start(
        move |shared| {
            // Delayed source scheduling is inside the SAME observation, including
            // time before a Reader object is handed back to the owner.
            std::thread::sleep(Duration::from_millis(100));
            reader(shared)
        },
        move || {
            seen.store(true, Ordering::Release);
            factory()
        },
        Duration::from_millis(50),
    );
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert!(
        before.elapsed() >= Duration::from_millis(100),
        "source factory must be exercised"
    );
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
    assert!(
        !invoked.load(Ordering::Acquire),
        "expired initialization cannot begin PG connect"
    );
}

#[test]
fn component_panicking_backend_factory_closes_admission_and_actual_threads_are_joined() {
    let mut owner = Owned::new();
    let result = owner.start::<Probe>(reader, || panic!("component initialization exit"), OBSERVE);
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert!(owner.shared.stopped());
    assert!(owner.shutdown(OBSERVE).cleanup_complete);
}
