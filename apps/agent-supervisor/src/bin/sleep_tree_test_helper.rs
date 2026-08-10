//! Test-only helper binary: builds a real, two-generation process tree so
//! `tests/process_group_kill.rs` can prove `process_group::terminate_tree`
//! kills a spawned child *and* that child's own child -- the shape the AMSI
//! incident actually had (the dangerous PowerShell script was a child
//! process the agent spawned, not the agent's own top-level process). Never
//! built into the release binary; not referenced by `main.rs`.
//!
//! Modes, selected by `argv[1]`:
//!
//! - `child` (default): spawns itself again in `leaf` mode as its own OS
//!   child -- ordinary `Command::spawn`, no process-group manipulation of its
//!   own, so the leaf inherits this process's process group exactly the way
//!   a real agent's own subprocess would. Prints `LEAF_PID=<pid>` to stdout
//!   (so the test, which only has a handle to *this* top-level process, can
//!   learn the grandchild's pid) and then blocks on the leaf's own exit.
//! - `leaf`: sleeps indefinitely. This is the process that must die from a
//!   `killpg` even though nothing in this test ever spawned it directly.

use std::env;
use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "child".to_owned());
    match mode.as_str() {
        "leaf" => sleep_forever(),
        "child" => run_as_child(),
        other => {
            eprintln!("sleep_tree_test_helper: unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}

fn run_as_child() {
    let exe = env::current_exe().expect("current_exe must resolve for the test helper itself");
    let mut leaf = Command::new(exe)
        .arg("leaf")
        .spawn()
        .expect("failed to spawn the leaf test process");
    println!("LEAF_PID={}", leaf.id());
    std::io::stdout().flush().expect("stdout flush must succeed");
    // Blocks until the leaf exits (or this process itself is killed, which a
    // real `killpg` does directly rather than through this wait returning).
    let _ = leaf.wait();
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(300));
    }
}
