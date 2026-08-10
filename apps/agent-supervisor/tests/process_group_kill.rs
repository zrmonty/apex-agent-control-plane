//! Proves `process_group::SupervisedChild::terminate_tree` actually kills a
//! real, spawned OS process tree -- not a mock, and not just the top-level
//! process. This is the shape the AMSI incident that motivated this whole
//! gateway actually had: the dangerous PowerShell one-liner was a *child
//! process the agent spawned*, not the agent's own top-level process, so a
//! kill that only reached the top of the tree would have left it running.
//!
//! The real proof (`terminate_tree_kills_a_spawned_child_and_its_own_child`)
//! is inherently POSIX-specific -- `killpg` has no Windows equivalent -- so
//! it is `#[cfg(unix)]`. The Windows counterpart proves only the weaker,
//! honestly-documented guarantee `process_group::SupervisedChild::terminate_tree`
//! states for that platform: the direct child dies; a grandchild is not
//! guaranteed to.

#[cfg(unix)]
mod unix {
    use std::collections::BTreeMap;
    use std::process::Stdio;
    use std::time::Duration;

    use apex_agent_supervisor::process_group;

    /// A real two-generation process tree, killed with one `terminate_tree`
    /// call on the top-level `SupervisedChild` -- the *grandchild* dying too
    /// is the property this test exists to prove, since the top-level
    /// process is the only one this test (or a real supervisor) ever spawns
    /// directly.
    #[tokio::test]
    async fn terminate_tree_kills_a_spawned_child_and_its_own_child() {
        let helper = env!("CARGO_BIN_EXE_sleep_tree_test_helper");
        let env = BTreeMap::new();
        let mut child = process_group::spawn_with_stdio(
            helper,
            &["child".to_owned()],
            &env,
            Stdio::null(),
            Stdio::piped(),
            Stdio::inherit(),
        )
        .expect("spawning the sleep-tree test helper must succeed");

        let direct_child_pid = child
            .id()
            .expect("the freshly spawned direct child must have a pid") as i32;

        let mut stdout = process_group::take_stdout(&mut child).expect("stdout must be piped");
        let grandchild_pid = read_leaf_pid(&mut stdout).await;
        assert_ne!(
            direct_child_pid, grandchild_pid,
            "the grandchild must be a genuinely different process from the direct child"
        );

        // Both processes are alive before the kill -- otherwise "they're dead
        // afterward" would prove nothing.
        assert!(
            process_alive(direct_child_pid),
            "the direct child must be alive before terminate_tree"
        );
        assert!(
            process_alive(grandchild_pid),
            "the grandchild must be alive before terminate_tree"
        );

        child
            .terminate_tree()
            .expect("terminate_tree must succeed");

        // The direct child is reaped via `child.wait()`, not the signal-0
        // poll `wait_until_dead` below uses for the grandchild: this test
        // process is the direct child's *real* OS parent, and `kill(pid, 0)`
        // cannot tell "zombie, SIGKILLed, awaiting reap by its real parent"
        // apart from "still actually running" -- both return success. Only
        // this process can reap it, and only `wait()`/`try_wait()` does that;
        // polling signal-0 without ever reaping would see a zombie forever
        // and time out even though the kill genuinely succeeded.
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("the killed direct child must be reaped by its real parent promptly")
            .expect("waiting on the killed direct child must succeed");
        assert!(
            !status.success(),
            "a SIGKILLed process must not report success"
        );

        // The grandchild is not this process's child -- there is no `wait()`
        // this process can call on it -- so it's checked the only way it can
        // be: signal-0 polling. It dies from its own SIGKILL (killpg signals
        // the whole group independently, not via the direct child relaying
        // anything), and once reparented to init after the direct child
        // terminates, init reaps it, at which point the signal-0 check
        // correctly stops finding it. Bounded polling, not a fixed sleep.
        wait_until_dead(grandchild_pid, Duration::from_secs(10)).await;
    }

    async fn read_leaf_pid(stdout: &mut tokio::process::ChildStdout) -> i32 {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(stdout).lines();
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("the helper must report the grandchild's pid promptly")
            .expect("reading the helper's LEAF_PID line must succeed")
            .expect("the helper must print a LEAF_PID line before this stream ends");
        line.strip_prefix("LEAF_PID=")
            .unwrap_or_else(|| panic!("the helper's first line must be LEAF_PID=<pid>, got {line:?}"))
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("the helper's leaf pid must be a valid integer, got {line:?}"))
    }

    fn process_alive(pid: i32) -> bool {
        // Signal 0: existence/permission check only, sends nothing. The
        // standard POSIX idiom for "is this pid still alive from here".
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
    }

    async fn wait_until_dead(pid: i32, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !process_alive(pid) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("pid {pid} was still alive {timeout:?} after terminate_tree");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use apex_agent_supervisor::process_group;

    /// The honestly-weaker Windows guarantee `terminate_tree`'s own doc
    /// comment states: the direct child dies. This does not and cannot
    /// prove a grandchild dies -- that is the documented gap, not something
    /// this test papers over.
    #[tokio::test]
    async fn terminate_tree_kills_the_direct_child() {
        let helper = env!("CARGO_BIN_EXE_sleep_tree_test_helper");
        let env = BTreeMap::new();
        let mut child = process_group::spawn(helper, &["leaf".to_owned()], &env)
            .expect("spawning the sleep-tree test helper must succeed");

        child
            .terminate_tree()
            .expect("terminate_tree must succeed");

        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("the killed direct child must exit promptly")
            .expect("waiting on the killed child must succeed");
        assert!(!status.success(), "a killed process must not report success");
    }
}
