use super::{concurrency::*, *};
use std::sync::{Mutex, atomic::Ordering};

struct Records(PathBuf);

impl Records {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("apex-batch-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn pids(&self) -> Option<Vec<i32>> {
        (0..4)
            .map(|batch| {
                std::fs::read_to_string(self.0.join(batch.to_string()))
                    .ok()?
                    .parse()
                    .ok()
            })
            .collect()
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        for batch in 0..4 {
            let _ = std::fs::remove_file(self.0.join(batch.to_string()));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn command_failure(error: command::CommandError) -> &'static str {
    match error {
        command::CommandError::Cancelled => "EXPECTED_CANCELLED",
        command::CommandError::Deadline => "EXPECTED_DEADLINE",
        command::CommandError::OutputLimit => "EXPECTED_OUTPUT_LIMIT",
        _ => "UNEXPECTED_COMMAND_ERROR",
    }
}

fn child_ownership(cancel_after_start: bool) {
    let records = Records::new();
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now()
        + if cancel_after_start {
            WATCHDOG
        } else {
            Duration::from_secs(2)
        };
    let errors = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        let owner = scope.spawn(|| {
            inspect_batches(
                Kind::Container,
                ids(64),
                deadline,
                &cancel,
                &|args, d, c| {
                    assert_eq!(d, deadline);
                    assert!(std::ptr::eq(c, &cancel));
                    let batch = usize::from_str_radix(&args[2], 16).unwrap() / 16;
                    let record = records.0.join(batch.to_string());
                    // Synthetic command only, using the same real child owner as Engine::run.
                    // The PID file is the explicit child-start latch. No Docker or socket.
                    let result = command::run_until(
                        CommandInput {
                            executable: Path::new("/bin/sh"),
                            arguments: &[
                                "-c".into(),
                                "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 20".into(),
                                "batch-child".into(),
                                record.into_os_string(),
                            ],
                            directory: Path::new("/"),
                            home: None,
                            budget: Duration::from_secs(30),
                            cancelled: c,
                        },
                        d,
                    );
                    result.map(Zeroizing::new).map_err(|error| {
                        errors.lock().unwrap().push(error);
                        command_failure(error)
                    })
                },
            )
        });
        let watchdog = Instant::now() + WATCHDOG;
        let pids = loop {
            if let Some(pids) = records.pids() {
                break pids;
            }
            if Instant::now() >= watchdog || owner.is_finished() {
                cancel.store(true, Ordering::Release);
                let result = owner.join();
                panic!("four real command children must start: {result:?}");
            }
            std::thread::yield_now();
        };
        if cancel_after_start {
            cancel.store(true, Ordering::Release);
        }
        let expected = if cancel_after_start {
            command::CommandError::Cancelled
        } else {
            command::CommandError::Deadline
        };
        assert_eq!(
            owner.join().unwrap().unwrap_err(),
            command_failure(expected)
        );
        assert_eq!(*errors.lock().unwrap(), vec![expected; 4]);
        // Not just logical completion: no exact command child is still waitable.
        for raw in pids {
            let waited = rustix::process::waitid(
                rustix::process::WaitId::Pid(rustix::process::Pid::from_raw(raw).unwrap()),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            );
            assert!(matches!(waited, Err(rustix::io::Errno::CHILD)));
        }
    });
}

#[test]
fn external_cancellation_reaps_all_four_real_children() {
    child_ownership(true);
}

#[test]
fn original_absolute_deadline_reaps_all_four_real_children() {
    child_ownership(false);
}

#[test]
fn real_command_preserves_pre_cancel_expired_deadline_and_output_limit() {
    for (cancelled, expired, expected) in [
        (true, false, command::CommandError::Cancelled),
        (false, true, command::CommandError::Deadline),
        (false, false, command::CommandError::OutputLimit),
    ] {
        let cancel = AtomicBool::new(cancelled);
        let deadline = if expired {
            Instant::now()
        } else {
            Instant::now() + WATCHDOG
        };
        let result = inspect_batches(Kind::Container, ids(64), deadline, &cancel, &|_, d, c| {
            assert_eq!(d, deadline);
            assert!(std::ptr::eq(c, &cancel));
            command::run_until(
                CommandInput {
                    executable: Path::new("/usr/bin/head"),
                    arguments: &["-c".into(), "262145".into(), "/dev/zero".into()],
                    directory: Path::new("/"),
                    home: None,
                    budget: Duration::from_secs(30),
                    cancelled: c,
                },
                d,
            )
            .map(Zeroizing::new)
            .map_err(command_failure)
        });
        assert_eq!(result.unwrap_err(), command_failure(expected));
    }
}
