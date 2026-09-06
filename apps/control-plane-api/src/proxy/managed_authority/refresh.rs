//! Root-owned physical filesystem worker, never a Tokio filesystem job.
use super::{
    Refused, protected,
    state::{Selection, State},
};
use std::{
    marker::PhantomData,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) struct Shared {
    state: Mutex<State>,
    stopped: AtomicBool,
    wake: Condvar,
    pause: Mutex<()>,
}
impl Shared {
    pub(super) fn current(&self) -> Result<Arc<Selection>, Refused> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Refused);
        }
        self.state
            .try_lock()
            .map_err(|_| Refused)?
            .current(Instant::now())
    }
    pub(super) fn recheck(&self, selected: &Selection) -> Result<(), Refused> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Refused);
        }
        self.state
            .try_lock()
            .map_err(|_| Refused)?
            .recheck(selected, Instant::now())
    }
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake.notify_all();
    }
}

/// !Send root owner: construct outside Tokio and retain beyond runtime teardown.
/// A stalled read remains owned; reporting timeout cannot spawn a replacement.
pub(super) struct RefreshOwner {
    pub shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
    attempted: bool,
    _root_only: PhantomData<Rc<()>>,
}
impl RefreshOwner {
    pub(super) fn new() -> Result<Self, Refused> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Refused);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::new()),
                stopped: AtomicBool::new(false),
                wake: Condvar::new(),
                pause: Mutex::new(()),
            }),
            handle: None,
            attempted: false,
            _root_only: PhantomData,
        })
    }
    pub(super) fn start(&mut self, path: PathBuf, base: PathBuf) -> Result<(), Refused> {
        self.start_with(
            move || protected::read(&path, &base),
            Duration::from_secs(15),
        )
    }
    fn start_with(
        &mut self,
        reader: impl FnMut() -> Result<Vec<u8>, Refused> + Send + 'static,
        observation: Duration,
    ) -> Result<(), Refused> {
        if self.attempted
            || self.shared.stopped.load(Ordering::Acquire)
            || tokio::runtime::Handle::try_current().is_ok()
        {
            return Err(Refused);
        }
        self.attempted = true;
        let shared = Arc::clone(&self.shared);
        let (initial, ready) = mpsc::sync_channel(1);
        self.handle = Some(
            thread::Builder::new()
                .name("apex-managed-policy".into())
                .spawn(move || {
                    let _stop = Stop(Arc::clone(&shared));
                    run(&shared, reader, initial);
                })
                .map_err(|_| Refused)?,
        );
        let result = ready
            .recv_timeout(observation.min(Duration::from_secs(15)))
            .map_err(|_| Refused)
            .and_then(|value| value);
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
    pub(super) fn shutdown(&mut self) -> Result<(), Refused> {
        self.shared.stop();
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Refused);
        }
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| Refused)?;
        }
        Ok(())
    }
}
impl Drop for RefreshOwner {
    fn drop(&mut self) {
        self.shared.stop();
        // Last-resort root cleanup never detaches the still-owned physical read.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
struct Stop(Arc<Shared>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

fn run(
    shared: &Shared,
    mut reader: impl FnMut() -> Result<Vec<u8>, Refused>,
    initial: mpsc::SyncSender<Result<(), Refused>>,
) {
    let mut first = Some(initial);
    while !shared.stopped.load(Ordering::Acquire) {
        let started = Instant::now();
        // The state lock is not held across filesystem work. Concurrent reads
        // see original-age expiry, never a refreshed timestamp before completion.
        let bytes = reader();
        let Ok(mut state) = shared.state.lock() else {
            return;
        };
        let result = match bytes {
            Ok(bytes) if !shared.stopped.load(Ordering::Acquire) => {
                state.publish(&bytes, started, Instant::now())
            }
            _ => {
                state.disable();
                Err(Refused)
            }
        };
        drop(state);
        if let Some(initial) = first.take() {
            let _ = initial.send(result);
        }
        if shared.stopped.load(Ordering::Acquire) {
            return;
        }
        // Cadence is after physical completion; no queued overlapping refresh.
        let Ok(pause) = shared.pause.lock() else {
            return;
        };
        if shared
            .wake
            .wait_timeout_while(pause, Duration::from_secs(1), |_| {
                !shared.stopped.load(Ordering::Acquire)
            })
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
