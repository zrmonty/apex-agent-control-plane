//! Spawns the supervised agent as the real OS parent of its own process
//! group, and kills that whole group -- not just the top process -- on
//! `force_stop`.
//!
//! # Why "real OS parent", specifically
//!
//! A PID alone carries no kill authority a compromised or racing process
//! cannot spoof or outlive: a file containing "the agent's PID is 4821" can
//! be stale (PIDs are reused), can be written by the very process being
//! supervised, and gives whoever reads it no guarantee that PID 4821 is
//! still the same program that wrote it. Being the actual `fork`/`exec`
//! parent removes all of that -- the kernel itself is what hands this
//! process the child's real lifecycle (`wait()` on an exited PID is only ever
//! meaningful to its real parent), and [`spawn`] puts the child in a *new*
//! process group with itself as the group leader
//! (`std::os::unix::process::CommandExt::process_group(0)`), so a single
//! `killpg` targeting that group id reaches the child and every descendant
//! it spawns that does not itself call `setsid`/`setpgid` -- which is exactly
//! the AMSI incident's own shape: the dangerous PowerShell one-liner was a
//! *child process the agent spawned*, and a kill that only reached the
//! agent's own top-level process would have left it running.

use std::collections::BTreeMap;
use std::io;
use std::process::{ExitStatus, Stdio};

/// Builds the `std::process::Command` that will become the supervised
/// agent's process, with its environment set **from scratch**
/// (`env_clear()`) rather than inherited, and -- on Unix -- placed into a new
/// process group with itself as leader.
///
/// `env` is expected to already be the *complete* child environment (built by
/// [`crate::child_env::build_child_env`]); this function adds nothing to it
/// and removes nothing from it. Stdio is left at `std::process::Command`'s
/// own default (piped) -- callers set it explicitly (see [`spawn`] and
/// [`spawn_with_stdio`]).
pub fn build_command(program: &str, args: &[String], env: &BTreeMap<String, String>) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.args(args);
    // The core of the credential-isolation property (see `crate::child_env`):
    // start from nothing, not from this process's own environment.
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        // New process group, this child as its own leader (pgid == its own
        // pid). Safe: stabilized on `std::process::Command` since Rust 1.64,
        // no `unsafe`/`pre_exec` required.
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
    }
    command
}

/// A spawned, supervised agent process.
pub struct SupervisedChild {
    inner: tokio::process::Child,
    /// The process group id to `killpg` on `force_stop`. Equal to the
    /// child's own pid, because [`build_command`] made it its own group
    /// leader. `None` only if the platform has no such concept (Windows).
    #[cfg_attr(not(unix), allow(dead_code))]
    pgid: Option<i32>,
}

/// Spawns `program`/`args` as a new OS process with environment `env`,
/// captured as the real OS parent (see the module docs for why that matters)
/// and, on Unix, as the leader of a fresh process group. Stdio is inherited
/// from this process, so an operator watching this supervisor's own logs
/// sees the agent's real console output.
pub fn spawn(program: &str, args: &[String], env: &BTreeMap<String, String>) -> io::Result<SupervisedChild> {
    spawn_with_stdio(program, args, env, Stdio::inherit(), Stdio::inherit(), Stdio::inherit())
}

/// As [`spawn`], but with explicit control over the child's stdio. `spawn`
/// itself always inherits; this variant exists for tests that need to
/// capture a spawned process's stdout (`tests/credential_isolation.rs` reads
/// back what a real child process observed of its own environment) without
/// affecting production behavior, which never calls this directly.
pub fn spawn_with_stdio(
    program: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
) -> io::Result<SupervisedChild> {
    let mut std_command = build_command(program, args, env);
    std_command.stdin(stdin).stdout(stdout).stderr(stderr);
    let mut tokio_command = tokio::process::Command::from(std_command);
    // This process's own `terminate_tree` is the intended shutdown path for
    // `force_stop`; drop-time kill is a backstop for the ordinary "the
    // supervisor process itself exited" case (a crash, a container restart)
    // so an unsupervised agent is not left running with nothing polling for
    // its own `force_stop` anymore.
    tokio_command.kill_on_drop(true);
    let child = tokio_command.spawn()?;
    let pgid = child.id().map(|pid| pid as i32);
    Ok(SupervisedChild { inner: child, pgid })
}

/// Takes the child's stdout handle for reading, when it was spawned with a
/// piped stdout (`spawn_with_stdio(..., Stdio::piped())`). `None` if stdout
/// was inherited or already taken.
pub fn take_stdout(child: &mut SupervisedChild) -> Option<tokio::process::ChildStdout> {
    child.inner.stdout.take()
}

impl SupervisedChild {
    /// The child's own pid, if it has not already been reaped.
    pub fn id(&self) -> Option<u32> {
        self.inner.id()
    }

    /// Awaits the child's own exit -- the *ordinary* shutdown path, when the
    /// agent finishes or crashes on its own rather than being force-stopped.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait().await
    }

    /// Kills the whole process group in one unconditional signal.
    ///
    /// **Unix:** `SIGKILL` to `-pgid`. Deliberately not a
    /// `SIGTERM`-then-wait-then-`SIGKILL` escalation: `force_stop` exists
    /// specifically for the case where the agent process cannot be trusted
    /// to cooperate with *any* signal, and a grace period is exactly the
    /// "ask nicely first" step every one of ADR-0005's cooperative controls
    /// already provides at a less severe layer. Uses [`nix::sys::signal::killpg`],
    /// whose public API is safe Rust (the `unsafe` FFI call into `kill(2)`
    /// lives inside `nix` itself), which is what lets this crate keep
    /// `unsafe_code = "forbid"` while still reaching a real POSIX
    /// process-group primitive.
    ///
    /// **Windows: best-effort only, and this is the honest gap, not a hidden
    /// one.** There is no POSIX process-group primitive on Windows; a
    /// faithful equivalent needs a Job Object the child is assigned to at
    /// creation time, which this v1 does not implement -- the project's
    /// actual deployment target is Linux containers (`deploy/` is
    /// Docker/compose throughout), and Windows support here is best-effort,
    /// not a blocker. This falls back to killing the direct child process
    /// only (`TerminateProcess` via `tokio::process::Child::start_kill`); a
    /// grandchild the agent spawned (this crate's own motivating scenario --
    /// the AMSI incident's PowerShell child process) is **not** guaranteed to
    /// die on Windows. Matches this codebase's existing precedent for
    /// stating a weaker Windows story explicitly rather than silently
    /// pretending parity (see `apps/control-plane-api/src/inbox.rs`'s
    /// directory-fsync comment for the tone).
    pub fn terminate_tree(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let Some(pgid) = self.pgid else {
                return Err(io::Error::other(
                    "supervised child has no known process group id (already reaped)",
                ));
            };
            nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pgid), nix::sys::signal::Signal::SIGKILL)
                .map_err(io::Error::other)
        }
        #[cfg(not(unix))]
        {
            self.inner.start_kill()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain, always-run half of the process-group proof: a spawned
    /// child actually dies. The real *tree* proof (a child's own child also
    /// dying via `killpg`) lives in `tests/process_group_kill.rs`, which
    /// needs the compiled `sleep_tree_test_helper` binary Cargo only builds
    /// for the `tests/` integration harness.
    #[tokio::test]
    async fn a_spawned_child_is_actually_killed() {
        let env = BTreeMap::new();
        #[cfg(unix)]
        let (program, args) = ("sh", vec!["-c".to_owned(), "sleep 300".to_owned()]);
        #[cfg(windows)]
        let (program, args) = (
            "cmd.exe",
            vec!["/C".to_owned(), "timeout /T 300".to_owned()],
        );
        let mut child = spawn(program, &args, &env).expect("spawn must succeed");
        assert!(child.id().is_some());
        child.terminate_tree().expect("terminate_tree must succeed");
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .expect("the killed child must exit promptly")
            .expect("wait must succeed");
        assert!(!status.success());
    }
}
