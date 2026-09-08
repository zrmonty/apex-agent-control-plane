use super::*;
use std::{sync::atomic::Ordering, time::Instant};

fn shell(script: &str, budget: Duration, cancelled: &AtomicBool) -> Result<Vec<u8>, CommandError> {
    // Shell is a synthetic test child only. Production adapters construct argv
    // for an administrator-protected executable, never a shell or RPC program.
    run(CommandInput {
        executable: Path::new("/bin/sh"),
        arguments: &["-c".into(), script.into()],
        directory: Path::new("/"),
        home: None,
        budget,
        cancelled,
    })
}

#[test]
fn exact_stdout_is_returned_without_stderr() {
    assert_eq!(
        shell(
            "printf output; printf secret-canary >&2",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap(),
        b"output"
    );
}

#[test]
fn nonzero_exit_never_returns_output() {
    assert_eq!(
        shell(
            "printf secret-canary; exit 17",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap_err(),
        CommandError::Exit
    );
}

#[test]
fn child_gets_no_inherited_home_or_credentials() {
    assert_eq!(
        shell(
            "printf '%s' \"${HOME-unset}:${APEX_COMMAND_CANARY-unset}\"",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap(),
        b"unset:unset"
    );
}

#[test]
fn stdin_is_closed() {
    assert_eq!(
        shell(
            "if read value; then exit 1; else printf eof; fi",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap(),
        b"eof"
    );
}

#[test]
fn each_output_stream_has_a_bound() {
    for script in [
        "/usr/bin/head -c 262145 /dev/zero",
        "/usr/bin/head -c 65537 /dev/zero >&2",
    ] {
        assert_eq!(
            shell(script, Duration::from_secs(2), &AtomicBool::new(false)).unwrap_err(),
            CommandError::OutputLimit
        );
    }
}

#[test]
fn exact_stdout_bound_is_accepted() {
    assert_eq!(
        shell(
            "/usr/bin/head -c 262144 /dev/zero",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap()
        .len(),
        262144
    );
}

#[test]
fn pre_cancel_and_zero_budget_refuse_before_child_spawn() {
    assert_eq!(
        shell("exit 0", Duration::from_secs(2), &AtomicBool::new(true)).unwrap_err(),
        CommandError::Cancelled
    );
    assert_eq!(
        shell("exit 0", Duration::ZERO, &AtomicBool::new(false)).unwrap_err(),
        CommandError::Deadline
    );
}

#[test]
fn deadline_kills_and_reaps_even_when_pipes_are_closed() {
    let start = Instant::now();
    assert_eq!(
        shell(
            "exec 1>&- 2>&-; exec /bin/sleep 20",
            Duration::from_millis(50),
            &AtomicBool::new(false)
        )
        .unwrap_err(),
        CommandError::Deadline
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn cancellation_is_observed_while_child_is_running() {
    let cancel = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            cancel.store(true, Ordering::Release);
        });
        assert_eq!(
            shell("exec /bin/sleep 20", Duration::from_secs(2), &cancel).unwrap_err(),
            CommandError::Cancelled
        );
    });
}

#[test]
fn normal_parent_exit_does_not_leave_a_pipe_holding_descendant() {
    let start = Instant::now();
    assert_eq!(
        shell(
            "/bin/sleep 20 & printf done",
            Duration::from_secs(2),
            &AtomicBool::new(false)
        )
        .unwrap(),
        b"done"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn invalid_inputs_are_rejected() {
    let cancelled = AtomicBool::new(false);
    let args = vec![OsString::from("x"); 97];
    for (executable, directory, arguments) in [
        (Path::new("sh"), Path::new("/"), &[][..]),
        (Path::new("/bin/sh"), Path::new("relative"), &[][..]),
        (Path::new("/bin/sh"), Path::new("/"), args.as_slice()),
    ] {
        assert_eq!(
            run(CommandInput {
                executable,
                directory,
                arguments,
                home: None,
                budget: Duration::from_secs(1),
                cancelled: &cancelled
            })
            .unwrap_err(),
            CommandError::Invalid
        );
    }
}

#[test]
fn timeout_has_reaped_the_exact_child_before_returning() {
    let parent = std::env::temp_dir();
    let directory = parent.join(format!("apex-command-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&directory).unwrap();
    let record = directory.join("pid");
    let result = run(CommandInput {
        executable: Path::new("/bin/sh"),
        arguments: &[
            "-c".into(),
            "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 20".into(),
            "owned-test".into(),
            record.as_os_str().to_owned(),
        ],
        directory: Path::new("/"),
        home: None,
        budget: Duration::from_millis(200),
        cancelled: &AtomicBool::new(false),
    });
    assert_eq!(result.unwrap_err(), CommandError::Deadline);
    let raw: i32 = std::fs::read_to_string(&record).unwrap().parse().unwrap();
    let pid = rustix::process::Pid::from_raw(raw).unwrap();
    let waited = rustix::process::waitid(
        rustix::process::WaitId::Pid(pid),
        rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT,
    );
    assert!(
        matches!(waited, Err(rustix::io::Errno::CHILD)),
        "no waitable child may remain"
    );
    assert_eq!(directory.parent(), Some(parent.as_path()));
    std::fs::remove_file(record).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
