use super::*;

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn terminal_without_exit_code_keeps_ownership_and_unresolved_history() {
    for recovering in [false, true] {
        let (fixture, journal, record) = setup(Phase::StartIntent);
        let mut terminal_without_code = inspection(false, 0, 123);
        terminal_without_code["ExitCode"] = serde_json::Value::Null;
        let reply = response(200, serde_json::to_vec(&terminal_without_code).unwrap());
        let peer = Peer::hold(&fixture, reply.clone());
        let job = Job::spawn(&fixture, &journal, &record, recovering);
        peer.wait();
        peer.inspect(&record);
        let pending = Peer::hold(&fixture, reply);
        pending.wait();
        job.pending();
        persisted(&journal, &record, Phase::StartIntent);
        job.shutdown.send(true).unwrap();
        pending.inspect(&record);
        assert!(job.result().is_err());
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::StartIntent);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn stdout_eof_and_expired_cancelled_start_keep_ownership_until_exact_exit() {
    let (fixture, journal, record) = setup(Phase::StartIntent);
    let peer = Peer::hold(&fixture, response(200, frame(1, b"{}\n")));
    // Let the real start read reach EOF before beginning physical cleanup.
    assert_eq!(&*peer.start(&fixture, &record).unwrap(), b"{}\n");
    persisted(&journal, &record, Phase::StartIntent);

    let cancelled = AtomicBool::new(true);
    assert!(
        fixture
            .engine
            .health_start(&record.exec_id, Instant::now(), &cancelled)
            .is_err()
    );
    no_dispatch(&fixture);
    let job = Job::spawn(&fixture, &journal, &record, false);
    for (running, pid) in [(true, 123), (false, 0)] {
        let peer = Peer::hold(&fixture, inspect_reply(running, 0, pid));
        peer.wait();
        job.pending();
        persisted(&journal, &record, Phase::StartIntent);
        peer.inspect(&record);
    }
    let terminal = Peer::hold(&fixture, inspect_reply(false, 0, 123));
    terminal.wait();
    job.pending();
    persisted(&journal, &record, Phase::StartIntent);
    terminal.inspect(&record);
    assert_eq!(job.result(), Ok(Some(0)));
    let journal = reopen(&fixture, journal);
    persisted(&journal, &record, Phase::Finished);
    no_dispatch(&fixture);
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn shutdown_during_terminal_inspection_preserves_unresolved_intent() {
    for recovering in [false, true] {
        let (fixture, journal, record) = setup(Phase::StartIntent);
        let peer = Peer::hold(&fixture, inspect_reply(false, 0, 123));
        let job = Job::spawn(&fixture, &journal, &record, recovering);
        peer.wait();
        job.pending();
        job.shutdown.send(true).unwrap();
        peer.inspect(&record);
        assert!(
            job.result().is_err(),
            "shutdown must refuse terminal result"
        );
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::StartIntent);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn successful_and_failed_exit_are_distinct_and_durable_before_return() {
    for exit in [0, 17] {
        let (fixture, journal, record) = setup(Phase::StartIntent);
        let peer = Peer::hold(&fixture, inspect_reply(false, exit, 123));
        let job = Job::spawn(&fixture, &journal, &record, false);
        peer.wait();
        job.pending();
        persisted(&journal, &record, Phase::StartIntent);
        peer.inspect(&record);
        assert_eq!(job.result(), Ok(Some(exit)));
        persisted(&journal, &record, Phase::Finished);
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::Finished);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn inspect_errors_and_wrong_identity_never_release_or_restart_the_exec() {
    let mut wrong_exec = inspection(false, 0, 123);
    wrong_exec["ID"] = serde_json::json!("e".repeat(64));
    let mut wrong_container = inspection(false, 0, 123);
    wrong_container["ContainerID"] = serde_json::json!("e".repeat(64));
    for reply in [
        response(500, b"unavailable".to_vec()),
        response(200, b"{".to_vec()),
        Vec::new(),
        response(200, serde_json::to_vec(&wrong_exec).unwrap()),
        response(200, serde_json::to_vec(&wrong_container).unwrap()),
    ] {
        let (fixture, journal, record) = setup(Phase::StartIntent);
        let peer = Peer::hold(&fixture, reply);
        let job = Job::spawn(&fixture, &journal, &record, false);
        peer.wait();
        peer.inspect(&record);
        let pending = Peer::hold(&fixture, inspect_reply(true, 0, 123));
        pending.wait();
        job.pending();
        persisted(&journal, &record, Phase::StartIntent);
        job.shutdown.send(true).unwrap();
        pending.inspect(&record);
        assert!(job.result().is_err());
        let journal = reopen(&fixture, journal);
        persisted(&journal, &record, Phase::StartIntent);
        no_dispatch(&fixture);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn uncertain_completion_sidecar_refuses_success_and_quarantines_restart() {
    let (fixture, journal, record) = setup(Phase::StartIntent);
    let path = fixture.root.join("journal").join(format!(
        "health-exec-{}.json",
        record.binding.process_instance_id
    ));
    let before = fs::read(&path).unwrap();
    let peer = Peer::hold(&fixture, inspect_reply(false, 0, 123));
    let job = Job::spawn(&fixture, &journal, &record, false);
    peer.wait();
    // A real incomplete atomic-write artifact, not a mock Journal success/failure.
    let next = path.with_extension("json.next");
    let pending_write = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&next)
        .unwrap();
    pending_write
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    pending_write.sync_all().unwrap();
    peer.inspect(&record);
    assert!(job.result().is_err());
    assert!(journal.health_record(&record.binding).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let journal = reopen(&fixture, journal);
    assert!(journal.health_record(&record.binding).is_err());
    no_dispatch(&fixture);
}
