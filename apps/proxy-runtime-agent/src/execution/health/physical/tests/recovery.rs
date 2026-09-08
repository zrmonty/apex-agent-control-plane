use super::*;

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn created_null_exit_is_cleanup_only_when_exact_exec_never_started() {
    let (fixture, journal, record) = setup(Phase::Created);
    let journal = reopen(&fixture, journal);
    let mut never_started = inspection(false, 0, 0);
    never_started["ExitCode"] = serde_json::Value::Null;
    let peer = Peer::hold(
        &fixture,
        response(200, serde_json::to_vec(&never_started).unwrap()),
    );
    let job = Job::spawn(&fixture, &journal, &record, true);
    peer.wait();
    peer.inspect(&record);
    assert_eq!(job.result(), Ok(None));
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::Finished);
    no_dispatch(&fixture);
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn shutdown_of_unknown_exec_reopens_same_history_for_cleanup_only_recovery() {
    let (fixture, journal, record) = setup(Phase::StartIntent);
    let peer = Peer::hold(&fixture, inspect_reply(true, 0, 123));
    let job = Job::spawn(&fixture, &journal, &record, false);
    peer.wait();
    job.pending();
    job.shutdown.send(true).unwrap();
    peer.inspect(&record);
    assert!(job.result().is_err());
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::StartIntent);
    let previous = journal.health_record(&record.binding).unwrap().unwrap();
    let peer = Peer::hold(&fixture, inspect_reply(false, 17, 123));
    let recovery = Job::spawn(&fixture, &journal, &previous, true);
    peer.wait();
    peer.inspect(&record);
    assert_eq!(recovery.result(), Ok(None));
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::Finished);
    no_dispatch(&fixture);
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn restarted_start_intent_inspects_original_exec_and_returns_cleanup_only() {
    for exit in [0, 17] {
        let (fixture, journal, record) = setup(Phase::StartIntent);
        // Simulate an ambiguous start response using the actual Unix transport.
        let peer = Peer::hold(&fixture, Vec::new());
        assert!(peer.start(&fixture, &record).is_err());
        persisted(&journal, &record, Phase::StartIntent);
        let journal = reopen(&fixture, journal);
        let previous = journal.health_record(&record.binding).unwrap().unwrap();
        let peer = Peer::hold(&fixture, inspect_reply(false, exit, 123));
        let job = Job::spawn(&fixture, &journal, &previous, true);
        peer.wait();
        peer.inspect(&record);
        // Recovery's result contains neither an exit sample nor readiness data.
        assert_eq!(job.result(), Ok(None));
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::Finished);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn ambiguous_create_keeps_history_and_recovery_never_dispatches_a_replacement() {
    let (fixture, journal, record) = setup(Phase::CreateIntent);
    // Read the actual create request, then close without its daemon exec ID.
    let peer = Peer::hold(&fixture, Vec::new());
    let engine = Arc::clone(&fixture);
    std::thread::scope(|scope| {
        let create = scope.spawn(|| {
            engine.engine.health_create(
                &record.container_id,
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )
        });
        peer.wait();
        peer.answer(&format!(
            "POST /v1.47/containers/{}/exec",
            record.container_id
        ));
        assert!(create.join().unwrap().is_err());
    });
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::CreateIntent);
    let job = Job::spawn(&fixture, &journal, &record, true);
    assert!(job.result().is_err());
    persisted(&journal, &record, Phase::CreateIntent);
    no_dispatch(&fixture);
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn created_recovery_requires_exact_never_started_observation() {
    for (running, pid, allowed) in [(false, 0, true), (true, 123, false), (false, 123, false)] {
        let (fixture, journal, record) = setup(Phase::Created);
        let journal = reopen(&fixture, journal);
        let peer = Peer::hold(&fixture, inspect_reply(running, 0, pid));
        let job = Job::spawn(&fixture, &journal, &record, true);
        peer.wait();
        job.pending();
        persisted(&journal, &record, Phase::Created);
        peer.inspect(&record);
        let result = job.result();
        if allowed {
            assert_eq!(result, Ok(None));
        } else {
            assert!(result.is_err(), "must not adopt a started process");
        }
        let journal = reopen(&fixture, journal);
        persisted(
            &journal,
            &record,
            if allowed {
                Phase::Finished
            } else {
                Phase::Created
            },
        );
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn created_inspect_errors_preserve_original_history_after_restart() {
    let mut wrong = inspection(false, 0, 0);
    wrong["ContainerID"] = serde_json::json!("e".repeat(64));
    for reply in [
        response(503, Vec::new()),
        response(200, serde_json::to_vec(&wrong).unwrap()),
    ] {
        let (fixture, journal, record) = setup(Phase::Created);
        let peer = Peer::hold(&fixture, reply);
        let job = Job::spawn(&fixture, &journal, &record, true);
        peer.wait();
        peer.inspect(&record);
        assert!(job.result().is_err());
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::Created);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn shutdown_during_created_inspection_keeps_history_for_restart() {
    let (fixture, journal, record) = setup(Phase::Created);
    let peer = Peer::hold(&fixture, inspect_reply(false, 0, 0));
    let job = Job::spawn(&fixture, &journal, &record, true);
    peer.wait();
    job.shutdown.send(true).unwrap();
    peer.inspect(&record);
    assert!(
        job.result().is_err(),
        "shutdown must refuse created recovery"
    );
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::Created);
    no_dispatch(&fixture);
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn already_finished_recovery_returns_no_sample_and_never_dispatches() {
    let (fixture, journal, record) = setup(Phase::Finished);
    let journal = reopen(&fixture, journal);
    let job = Job::spawn(&fixture, &journal, &record, true);
    assert_eq!(job.result(), Ok(None));
    persisted(&journal, &record, Phase::Finished);
    no_dispatch(&fixture);
}
