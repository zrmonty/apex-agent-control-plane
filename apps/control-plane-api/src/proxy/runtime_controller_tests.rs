use super::*;

#[test]
fn only_explicit_authenticated_refusal_can_retry_within_original_budget() {
    let end = Instant::now() + Duration::from_secs(10);
    let refusal = ProxyError::new(
        "RUNTIME_EXECUTION_RETRYABLE",
        "Runtime temporarily refused.",
    );
    assert!(retry_allowed(&refusal, 0, end));
    assert!(
        !retry_allowed(&unavailable(), 0, end),
        "unknown transport completion must not trigger replacement"
    );
    assert!(!retry_allowed(&refusal, 2, end));
    assert!(!retry_allowed(
        &refusal,
        0,
        Instant::now() + Duration::from_millis(100)
    ));
}

fn shared() -> Shared {
    Shared {
        stopped: AtomicBool::new(false),
        active: AtomicBool::new(false),
        scan_ok: AtomicBool::new(false),
        in_flight: Mutex::new(BTreeSet::new()),
        last_response: Mutex::new(None),
    }
}
fn key(n: usize) -> (String, String, String) {
    ("workspace".into(), "namespace".into(), format!("proxy-{n}"))
}

#[test]
fn physical_slots_are_global_exact_proxy_bounded_and_not_freed_by_timeout() {
    let shared = shared();
    for n in 0..CAPACITY {
        assert!(shared.reserve(key(n)).unwrap());
    }
    assert!(!shared.reserve(key(0)).unwrap());
    assert!(!shared.reserve(key(CAPACITY)).unwrap());
    assert!(check(&shared, Instant::now() - Duration::from_millis(1)).is_err());
    assert_eq!(shared.in_flight.lock().unwrap().len(), CAPACITY);
    assert!(
        !shared.reserve(key(CAPACITY)).unwrap(),
        "deadline must not mint replacement capacity"
    );
    shared.in_flight.lock().unwrap().remove(&key(0));
    assert!(shared.reserve(key(CAPACITY)).unwrap());
    shared.stopped.store(true, Ordering::Release);
    shared.in_flight.lock().unwrap().clear();
    assert!(!shared.reserve(key(0)).unwrap());
}

#[test]
fn health_needs_live_scan_and_authenticated_dependency_response_and_latches_stop() {
    let shared = Arc::new(shared());
    let status = RuntimeExecutionStatus(Arc::clone(&shared));
    status.activate();
    assert!(!status.healthy());
    shared.scan_ok.store(true, Ordering::Release);
    assert!(!status.healthy());
    *shared.last_response.lock().unwrap() = Some(Instant::now());
    assert!(status.healthy());
    *shared.last_response.lock().unwrap() = Some(Instant::now() - LEASE_TTL);
    assert!(!status.healthy());
    *shared.last_response.lock().unwrap() = Some(Instant::now());
    drop(Stop(shared));
    assert!(!status.healthy());
}

#[test]
fn partial_root_shutdown_retains_physical_thread_until_cleanup_finishes() {
    let mut owner = RuntimeExecutionOwner::new(
        RuntimeExecutionConfig::ownership_test_value(),
        "component-only",
    )
    .unwrap();
    let status = owner.status();
    let (release, blocked) = mpsc::sync_channel(1);
    let (entered, wait_entered) = mpsc::sync_channel(1);
    let (cleaned, wait_cleaned) = mpsc::sync_channel(1);
    owner.workers.push(thread::spawn(move || {
        entered.send(()).unwrap();
        blocked.recv().unwrap();
        cleaned.send(()).unwrap();
    }));
    wait_entered.recv().unwrap();
    // Model failure after the first owned spawn, before subsequent startup.
    owner.attempted = true;
    assert!(owner.start().is_err());
    let (done, finished) = mpsc::sync_channel(1);
    let joining = thread::spawn(move || {
        owner.shutdown().unwrap();
        done.send(()).unwrap();
    });
    assert!(finished.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(!status.healthy());
    assert!(wait_cleaned.try_recv().is_err());
    release.send(()).unwrap();
    wait_cleaned.recv().unwrap();
    finished.recv().unwrap();
    joining.join().unwrap();
}
