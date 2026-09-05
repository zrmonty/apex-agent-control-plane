//! Protocol component peers are NOT browser acceptance evidence.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn driver(program: &str, before_read: impl FnOnce() + Send + 'static) -> Driver {
    let mut command = Command::new("node");
    command
        .args(["--input-type=module", "-e", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .spawn()
        .expect("Node is required for protocol component tests");
    let (send, phases) = mpsc::sync_channel(8);
    let mut driver = Driver {
        child,
        input: None,
        phases,
        reader: None,
        diagnostics: None,
    };
    driver.input = driver.child.stdin.take();
    let output = driver.child.stdout.take().unwrap();
    driver.reader = Some(std::thread::spawn(move || {
        before_read();
        read_phases(output, send)
    }));
    driver
}

fn exited(driver: &mut Driver) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = driver.child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        assert!(
            Instant::now() < deadline,
            "owned component Node did not exit"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn exited_runner_does_not_overtake_buffered_final_marker() {
    let (release, gate) = mpsc::channel();
    let mut driver = driver("process.stdout.write('UI_JOURNEY_PASSED\\n');", move || {
        gate.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    exited(&mut driver);
    let runtime = runtime();
    // Observe exit before the reader may deliver any already-written bytes.
    // Catch/release even on RED so its owned reader cannot stall fixture Drop.
    let waiting = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(30), driver.wait(Phase::Passed)).await
        })
    }));
    let _ = release.send(());
    assert!(
        matches!(waiting, Ok(Err(_))),
        "wait must await reader delivery, not fail on process exit"
    );
    runtime.block_on(driver.wait(Phase::Passed));
    drop(runtime);
    driver.finish();
}

#[test]
fn finalization_requires_clean_exhausted_protocol_not_just_exit_zero() {
    for suffix in [
        "private-invalid-line\\n",
        "UI_JOURNEY_PASSED\\n",
        "UI_OFFLINE_OBSERVED\\n",
    ] {
        let mut driver = driver(
            &format!("process.stdout.write('UI_JOURNEY_PASSED\\n{suffix}');"),
            || {},
        );
        let runtime = runtime();
        runtime.block_on(driver.wait(Phase::Passed));
        drop(runtime);
        exited(&mut driver);
        assert!(
            catch_unwind(AssertUnwindSafe(|| driver.finish())).is_err(),
            "trailing output must invalidate final success"
        );
    }
}

#[test]
fn complete_three_phase_stream_with_exit_zero_is_accepted() {
    let mut driver = driver(
        "process.stdout.write('UI_READY_FOR_RESTART\\nUI_OFFLINE_OBSERVED\\nUI_JOURNEY_PASSED\\n');",
        || {},
    );
    let runtime = runtime();
    runtime.block_on(driver.wait(Phase::Restart));
    driver.wait_offline();
    runtime.block_on(driver.wait(Phase::Passed));
    drop(runtime);
    driver.finish();
}

#[test]
fn success_marker_does_not_mask_failed_process_exit() {
    let mut driver = driver(
        "process.stdout.write('UI_JOURNEY_PASSED\\n');process.exitCode=1;",
        || {},
    );
    let runtime = runtime();
    runtime.block_on(driver.wait(Phase::Passed));
    drop(runtime);
    assert!(catch_unwind(AssertUnwindSafe(|| driver.finish())).is_err());
}

#[test]
fn configured_runner_path_is_accepted_by_node() {
    // Parse the actual entrypoint through precisely the configured cwd/argv.
    // --check cannot start the browser, contact a provider, or mutate the BFF.
    let configured = runner_command();
    let result = Command::new(configured.get_program())
        .arg("--check")
        .args(configured.get_args())
        .current_dir(configured.get_current_dir().unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Node syntax check unavailable");
    assert!(result.success(), "Node rejected the configured runner path");
}
