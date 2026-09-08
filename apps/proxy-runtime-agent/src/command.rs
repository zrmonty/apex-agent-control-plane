//! Synchronous Linux child ownership, for the later fixed-capacity effect owner.
//! Not a task executor: callers must never run this on a Tokio worker. Kernel
//! spawn/reap cannot be forcibly time-bounded; ownership is retained until reap.
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, WaitIdOptions, kill_process_group, waitid},
};
use std::{
    ffi::OsString,
    io::{ErrorKind, Read},
    os::{fd::AsFd, unix::process::CommandExt},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandError {
    Invalid,
    Cancelled,
    Deadline,
    OutputLimit,
    Io,
    Exit,
}

pub(crate) struct CommandInput<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [OsString],
    pub directory: &'a Path,
    pub home: Option<&'a Path>,
    pub budget: Duration,
    pub cancelled: &'a AtomicBool,
}

pub(crate) fn run(input: CommandInput<'_>) -> Result<Vec<u8>, CommandError> {
    let deadline = Instant::now() + input.budget.min(Duration::from_secs(30));
    run_until(input, deadline)
}

pub(crate) fn run_until(
    input: CommandInput<'_>,
    deadline: Instant,
) -> Result<Vec<u8>, CommandError> {
    run_inner(input, deadline, None)
}
pub(crate) fn run_guarded(
    input: CommandInput<'_>,
    gate: &mut dyn Dispatch,
) -> Result<Vec<u8>, &'static str> {
    let deadline = gate.deadline()?;
    run_inner(input, deadline, Some(gate)).map_err(|_| "RUNTIME_NETWORK_COMMAND_REFUSED")
}
pub(crate) trait Dispatch {
    fn deadline(&self) -> Result<Instant, &'static str>;
    fn check(&mut self) -> Result<(), &'static str>;
    fn spawn_attempt(&mut self);
}
fn run_inner(
    input: CommandInput<'_>,
    deadline: Instant,
    mut gate: Option<&mut dyn Dispatch>,
) -> Result<Vec<u8>, CommandError> {
    let deadline = std::cell::Cell::new(
        deadline.min(Instant::now() + input.budget.min(Duration::from_secs(30))),
    );
    let check = || {
        if input.cancelled.load(Ordering::Acquire) {
            Err(CommandError::Cancelled)
        } else if Instant::now() >= deadline.get() {
            Err(CommandError::Deadline)
        } else {
            Ok(())
        }
    };
    check()?;
    if !input.executable.is_absolute()
        || !input.directory.is_absolute()
        || input.executable.as_os_str().len() > 4096
        || input.directory.as_os_str().len() > 4096
        || input.arguments.len() > 96
        || input.arguments.iter().any(|arg| arg.len() > 4096)
    {
        return Err(CommandError::Invalid);
    }
    if input
        .home
        .is_some_and(|path| !path.is_absolute() || path.as_os_str().len() > 4096)
    {
        return Err(CommandError::Invalid);
    }
    let mut command = Command::new(input.executable);
    command
        .args(input.arguments)
        .current_dir(input.directory)
        .env_clear();
    if let Some(home) = input.home {
        command.env("HOME", home);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    check()?;
    #[cfg(test)]
    crate::execution::testing::at(crate::execution::testing::Point::Spawn, None)
        .map_err(|_| CommandError::Cancelled)?;
    check()?;
    if let Some(gate) = &mut gate {
        #[cfg(test)]
        crate::execution::testing::at(
            crate::execution::testing::Point::NetworkSpawn,
            Some(deadline.get()),
        )
        .map_err(|_| CommandError::Cancelled)?;
        gate.check().map_err(|_| CommandError::Cancelled)?;
        // A fresh callback may shorten its lease. Never keep the earlier, longer
        // command clock, nor extend the original job/command cap on renewal.
        deadline.set(
            deadline
                .get()
                .min(gate.deadline().map_err(|_| CommandError::Deadline)?),
        );
        check()?;
        gate.spawn_attempt();
    }
    let child = command.spawn().map_err(|_| CommandError::Io)?;
    let mut owned = OwnedChild(Some(child));
    #[cfg(test)]
    if gate.is_some() {
        crate::execution::testing::at(
            crate::execution::testing::Point::NetworkChild,
            Some(deadline.get()),
        )
        .map_err(|_| CommandError::Cancelled)?;
    }
    let child = owned.0.as_mut().ok_or(CommandError::Io)?;
    let mut stdout = child.stdout.take().ok_or(CommandError::Io)?;
    let mut stderr = child.stderr.take().ok_or(CommandError::Io)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut output = Zeroizing::new(Vec::new());
    let mut stderr_count = 0;
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    loop {
        check()?;
        if !stdout_eof {
            stdout_eof = read_available(&mut stdout, &mut output, &mut 0, true, &check)?;
        }
        if !stderr_eof {
            stderr_eof =
                read_available(&mut stderr, &mut output, &mut stderr_count, false, &check)?;
        }
        if status.is_none() && owned.exited()? {
            // Observe with WNOWAIT, kill our process group BEFORE reaping its
            // leader. This prevents signalling a recycled PID/group after exit.
            status = Some(owned.finish()?);
        }
        if stdout_eof
            && stderr_eof
            && let Some(status) = status
        {
            check()?;
            return if status.success() {
                Ok(std::mem::take(&mut *output))
            } else {
                Err(CommandError::Exit)
            };
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), CommandError> {
    let flags = fcntl_getfl(fd).map_err(|_| CommandError::Io)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| CommandError::Io)
}

fn read_available(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    discarded: &mut usize,
    retain: bool,
    check: &impl Fn() -> Result<(), CommandError>,
) -> Result<bool, CommandError> {
    let mut scratch = Zeroizing::new([0; 4096]);
    // Bound one stream's work so a continuously writable pipe cannot starve
    // the other stream or the cancellation/deadline checks.
    for _ in 0..16 {
        check()?;
        match pipe.read(&mut *scratch) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                let used = if retain { output.len() } else { *discarded };
                let limit = if retain { 262_144 } else { 65_536 };
                if count > limit - used {
                    return Err(CommandError::OutputLimit);
                }
                if retain {
                    output.extend_from_slice(&scratch[..count]);
                } else {
                    *discarded += count;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(CommandError::Io),
        }
    }
    Ok(false)
}

// Only this owner may reap the child. The agent process must not install a
// SIGCHLD auto-reaper. Trusted tools must not escape their process group; this
// is lifecycle containment, not a sandbox for caller-supplied executables.
struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn exited(&self) -> Result<bool, CommandError> {
        let child = self.0.as_ref().ok_or(CommandError::Io)?;
        let pid = Pid::from_raw(i32::try_from(child.id()).map_err(|_| CommandError::Io)?)
            .ok_or(CommandError::Io)?;
        waitid(
            rustix::process::WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .map(|status| status.is_some())
        .map_err(|_| CommandError::Io)
    }

    fn finish(&mut self) -> Result<ExitStatus, CommandError> {
        let child = self.0.as_mut().ok_or(CommandError::Io)?;
        let pid = Pid::from_raw(i32::try_from(child.id()).map_err(|_| CommandError::Io)?)
            .ok_or(CommandError::Io)?;
        let _ = kill_process_group(pid, Signal::KILL);
        let _ = child.kill();
        // Do not release the worker/child ownership on a reported timeout.
        // Reaping can outlast the requested budget under a stuck kernel.
        let result = child.wait().map_err(|_| CommandError::Io);
        if result.is_ok() {
            self.0 = None;
        }
        result
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests;
