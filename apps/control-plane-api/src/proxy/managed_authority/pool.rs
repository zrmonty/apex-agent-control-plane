//! Private bounded physical worker; no database object crosses onto Tokio.
use super::Refused;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, oneshot};

pub(super) type Check = Arc<dyn Fn() -> Result<(), Refused> + Send + Sync>;
type Job<S> = Box<dyn FnOnce(&mut S) + Send>;
pub(super) struct Owner<S> {
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    attempted: bool,
    _root: PhantomData<Rc<()>>,
    _backend: PhantomData<fn(S)>,
}
pub(super) struct Client<S> {
    inner: Arc<Facade<S>>,
}
struct Facade<S> {
    sender: SyncSender<Job<S>>,
    stop: Arc<AtomicBool>,
    slots: Arc<Semaphore>,
}
impl<S> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
impl<S> Drop for Facade<S> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
impl<S: 'static> Owner<S> {
    pub(super) fn new() -> Result<Self, Refused> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Refused);
        }
        Ok(Self {
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
            attempted: false,
            _root: PhantomData,
            _backend: PhantomData,
        })
    }
    pub(super) fn start(
        &mut self,
        factory: impl FnOnce() -> Result<S, Refused> + Send + 'static,
    ) -> Result<Client<S>, Refused> {
        if self.attempted
            || self.stop.load(Ordering::Acquire)
            || tokio::runtime::Handle::try_current().is_ok()
        {
            return Err(Refused);
        }
        self.attempted = true;
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel::<Job<S>>(8);
        let (ready, initial) = mpsc::sync_channel(1);
        let stop = Arc::clone(&self.stop);
        self.handle = Some(
            thread::Builder::new()
                .name("apex-managed-postgres".into())
                .spawn(move || {
                    let _stop = Cancel(Arc::clone(&stop));
                    let receiver = receiver;
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    let mut backend = match factory() {
                        Ok(value) => value,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    if ready.send(Ok(())).is_err() {
                        return;
                    }
                    while !stop.load(Ordering::Acquire) {
                        match receiver.recv_timeout(Duration::from_millis(25)) {
                            Ok(job) => {
                                if stop.load(Ordering::Acquire) {
                                    break;
                                }
                                job(&mut backend);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    // Backend, queued jobs and socket runtimes all drop on this thread.
                })
                .map_err(|_| Refused)?,
        );
        let result = initial
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| Refused)
            .and_then(|value| value);
        if result.is_err() || started.elapsed() >= Duration::from_secs(15) {
            self.stop.store(true, Ordering::Release);
            return Err(Refused);
        }
        Ok(Client {
            inner: Arc::new(Facade {
                sender,
                stop: Arc::clone(&self.stop),
                slots: Arc::new(Semaphore::new(8)),
            }),
        })
    }
    pub(super) fn shutdown(&mut self) -> Result<(), Refused> {
        self.stop.store(true, Ordering::Release);
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Refused);
        }
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| Refused)?;
        }
        Ok(())
    }
}
impl<S> Drop for Owner<S> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
impl<S: 'static> Client<S> {
    pub(super) async fn request<T: Send + 'static>(
        &self,
        started: Instant,
        budget: Duration,
        fresh: Check,
        operation: impl FnOnce(&mut S, &dyn Fn() -> Result<(), Refused>) -> Result<T, Refused>
        + Send
        + 'static,
    ) -> Result<T, Refused> {
        let budget = budget.min(Duration::from_secs(10));
        let deadline = started.checked_add(budget).ok_or(Refused)?;
        let stop = Arc::clone(&self.inner.stop);
        let current: Check = Arc::new(move || {
            if stop.load(Ordering::Acquire)
                || Instant::now()
                    .checked_duration_since(started)
                    .is_none_or(|age| age >= budget)
            {
                return Err(Refused);
            }
            fresh()
        });
        current()?;
        let slot = Arc::clone(&self.inner.slots)
            .try_acquire_owned()
            .map_err(|_| Refused)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(Arc::clone(&cancelled));
        let (reply, response) = oneshot::channel();
        let job_current = Arc::clone(&current);
        let job = Box::new(move |backend: &mut S| {
            // A cancelled reply never releases this owned physical capacity.
            let _physical_slot = slot;
            let check = || {
                if cancelled.load(Ordering::Acquire) || reply.is_closed() {
                    return Err(Refused);
                }
                job_current()
            };
            let result = check().and_then(|()| operation(backend, &check));
            let result = check().and(result);
            let _ = reply.send(result);
        });
        self.inner.sender.try_send(job).map_err(|_| Refused)?;
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response).await;
        // A ready reply cannot win against an overdue timer or revoked profile.
        current()?;
        result.map_err(|_| Refused)?.map_err(|_| Refused)?
    }
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
