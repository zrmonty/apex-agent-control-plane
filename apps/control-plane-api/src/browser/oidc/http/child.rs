//! Owned test subprocess wait; no detached Tokio blocking-pool waiter.
use std::{
    future::Future,
    io,
    process::{Child, ExitStatus},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct OwnedChild {
    child: Arc<Mutex<Child>>,
    reaped: bool,
}

impl OwnedChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self
            .child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .try_wait()?;
        self.reaped = status.is_some();
        Ok(status)
    }

    fn kill_and_reap(&mut self) -> io::Result<()> {
        if !self.reaped {
            let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
            if child.try_wait()?.is_none() {
                child.kill()?;
                child.wait()?;
            }
            self.reaped = true;
        }
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Synchronous cleanup is intentional for these owned test children:
        // cancellation must kill AND reap, not spawn a cleanup task that the
        // enclosing runtime may abandon. No mutex guard crosses an await.
        let _ = self.kill_and_reap();
    }
}

pub(super) fn wait_child(
    child: Arc<Mutex<Child>>,
    deadline: Instant,
) -> impl Future<Output = io::Result<ExitStatus>> {
    // Capture ownership before the first poll, covering even an unpolled drop.
    let mut child = OwnedChild {
        child,
        reaped: false,
    };
    async move {
        loop {
            if Instant::now() >= deadline {
                child.kill_and_reap()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child watchdog expired",
                ));
            }
            let status = child.try_wait()?;
            if Instant::now() >= deadline {
                child.kill_and_reap()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child watchdog expired",
                ));
            }
            if let Some(status) = status {
                return Ok(status);
            }
            let wake = (Instant::now() + Duration::from_millis(5)).min(deadline);
            tokio::time::sleep_until(wake.into()).await;
        }
    }
}
