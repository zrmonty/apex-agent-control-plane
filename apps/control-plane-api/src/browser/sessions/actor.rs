//! Bounded async facade over the synchronous PostgreSQL session store.
//!
//! One named standard thread constructs, uses and drops PostgreSQL. The facade
//! holds no database/runtime object and never joins a worker. Eight queued jobs
//! are admitted with `try_send`; each request has one five-second deadline that
//! includes queue wait. Closed or expired queued replies never start a command.
//!
//! Final facade drop and explicit shutdown permanently signal stop. The worker
//! checks between commands and every 50 ms while idle, discards pending jobs and
//! drops its database owner before announcing completion. An in-flight command
//! remains subject to the synchronous store's transport deadlines; cancelling
//! its reply neither interrupts nor replays an uncertain mutation.

use super::{
    LoginAdmission, NewLoginAttempt, NewSession, PostgresSessionStore, RefreshCommit, StoredSession,
};
use crate::browser::{errors::BrowserError, security::LookupDigest};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

const QUEUE_CAPACITY: usize = 8;
const STARTUP_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const STOP_POLL: Duration = Duration::from_millis(50);
const WORKER_NAME: &str = "apex-browser-sessions";

/// Cloneable handle to a worker-owned PostgreSQL session store.
///
/// `RateLimited` means the queue or durable login quota refused admission.
/// `Unavailable` after submission
/// may leave an in-flight mutation's outcome uncertain; do not automatically retry.
#[derive(Clone)]
pub struct BrowserSessionStore {
    worker: Worker<PostgresSessionStore>,
}

impl fmt::Debug for BrowserSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserSessionStore")
            .finish_non_exhaustive()
    }
}

impl BrowserSessionStore {
    /// Synchronous startup entry point; call outside an entered Tokio runtime.
    ///
    /// # Errors
    /// Returns `Unavailable` for runtime misuse, failed startup or startup timeout.
    pub fn connect(connection_string: &str) -> Result<Self, BrowserError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(BrowserError::Unavailable);
        }
        let connection_string = Zeroizing::new(connection_string.to_owned());
        Ok(Self {
            worker: Worker::start(move || PostgresSessionStore::connect(&connection_string))?,
        })
    }

    /// Admit before provider work. An uncertain reply never permits a retry/refund.
    pub async fn admit_login(&self) -> Result<LoginAdmission, BrowserError> {
        self.worker.request(PostgresSessionStore::admit_login).await
    }

    /// Persist a bounded, encrypted login attempt.
    pub async fn create_login(&self, input: NewLoginAttempt) -> Result<(), BrowserError> {
        self.worker
            .request(move |store| store.create_login(input))
            .await
    }

    /// Atomically consume an unexpired login matching both browser and state.
    pub async fn take_login(
        &self,
        state: LookupDigest,
        browser: LookupDigest,
    ) -> Result<Option<NewLoginAttempt>, BrowserError> {
        self.worker
            .request(move |store| store.take_login(state, browser))
            .await
    }

    /// Persist a fresh encrypted session.
    pub async fn create_session(&self, input: NewSession) -> Result<(), BrowserError> {
        self.worker
            .request(move |store| store.create_session(input))
            .await
    }

    /// Read live state without extending idle expiry or claiming refresh.
    pub async fn load(&self, digest: LookupDigest) -> Result<Option<StoredSession>, BrowserError> {
        self.worker.request(move |store| store.load(digest)).await
    }

    /// Extend idle expiry only for the expected active generation.
    pub async fn touch(
        &self,
        digest: LookupDigest,
        expected: u64,
        idle_timeout_secs: u32,
    ) -> Result<bool, BrowserError> {
        self.worker
            .request(move |store| store.touch(digest, expected, idle_timeout_secs))
            .await
    }

    /// Claim one generation; the caller awaits its provider after this returns.
    pub async fn claim_refresh(
        &self,
        digest: LookupDigest,
        expected: u64,
    ) -> Result<Option<StoredSession>, BrowserError> {
        self.worker
            .request(move |store| store.claim_refresh(digest, expected))
            .await
    }

    /// Commit an already verified provider result under the refresh generation.
    pub async fn finish_refresh(&self, input: RefreshCommit) -> Result<bool, BrowserError> {
        self.worker
            .request(move |store| store.finish_refresh(input))
            .await
    }

    /// Revoke a session and erase its encrypted credentials.
    pub async fn revoke(&self, digest: LookupDigest) -> Result<bool, BrowserError> {
        self.worker.request(move |store| store.revoke(digest)).await
    }

    /// Perform the synchronous store's bounded expired-record cleanup.
    pub async fn prune_expired(&self) -> Result<u64, BrowserError> {
        self.worker
            .request(PostgresSessionStore::prune_expired)
            .await
    }

    /// Stop admission for every clone and await worker-owned PostgreSQL cleanup.
    ///
    /// Cancelling or timing out this wait leaves shutdown in effect. Completion
    /// is idempotent; the five-second wait returns `Unavailable` if cleanup has
    /// not finished. Neither this method nor `Drop` performs a blocking join.
    pub async fn shutdown(&self) -> Result<(), BrowserError> {
        self.worker.shutdown().await
    }
}

// Private generic seam permits explicitly labelled component scheduling tests.
// S is constructed inside the thread and never crosses it (even if S is !Send).
// Production instantiates this only with PostgresSessionStore; there is no public
// executor, backend injection, SQL command, or provider callback API.
type Job<S> = Box<dyn FnOnce(&mut S) + Send + 'static>;

struct Worker<S> {
    owner: Arc<Owner<S>>,
}

struct Owner<S> {
    sender: SyncSender<Job<S>>,
    stop: Arc<AtomicBool>,
    done: watch::Receiver<bool>,
}

// Created before the worker's receiver/store locals so even unwinding publishes
// completion only after both queued jobs and the backend owner have been dropped.
struct WorkerCompletion {
    stop: Arc<AtomicBool>,
    done: watch::Sender<bool>,
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.done.send_replace(true);
    }
}

impl<S> Clone for Worker<S> {
    fn clone(&self) -> Self {
        Self {
            owner: Arc::clone(&self.owner),
        }
    }
}

impl<S> Drop for Owner<S> {
    fn drop(&mut self) {
        // The thread holds only the stop flag, never an Arc<Owner>. Final-owner
        // drop, including destruction of an unpolled future, signals immediately.
        self.stop.store(true, Ordering::Release);
    }
}

impl<S: 'static> Worker<S> {
    fn start(
        factory: impl FnOnce() -> Result<S, BrowserError> + Send + 'static,
    ) -> Result<Self, BrowserError> {
        let deadline = Instant::now() + STARTUP_DEADLINE;
        let (sender, receiver) = mpsc::sync_channel::<Job<S>>(QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let (completed, done) = watch::channel(false);
        let owner = Arc::new(Owner {
            sender,
            stop: Arc::clone(&stop),
            done,
        });
        let (ready, startup) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(WORKER_NAME.into())
            .spawn(move || {
                let _completion = WorkerCompletion {
                    stop: Arc::clone(&stop),
                    done: completed,
                };
                // Move the capture into a local: it must drop before _completion,
                // including on early return or a panicking backend command.
                let receiver = receiver;
                let mut store = match factory() {
                    Ok(store) => store,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while !stop.load(Ordering::Acquire) {
                    match receiver.recv_timeout(STOP_POLL) {
                        Ok(job) => {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            job(&mut store);
                        }
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Both queued jobs and the full PostgreSQL runtime/socket owner
                // are destroyed here. No join or PG drop is delegated to Tokio.
            })
            .map_err(|_| BrowserError::Unavailable)?;

        // The single wait covers the factory's complete connect + migration.
        // On timeout/error, dropping owner signals stop, including the race where
        // ready was buffered just as this caller's deadline elapsed.
        startup
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| BrowserError::Unavailable)??;
        if Instant::now() >= deadline {
            return Err(BrowserError::Unavailable);
        }
        Ok(Self { owner })
    }

    async fn request<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut S) -> Result<T, BrowserError> + Send + 'static,
    ) -> Result<T, BrowserError> {
        let deadline = Instant::now() + REQUEST_DEADLINE;
        if self.owner.stop.load(Ordering::Acquire) {
            return Err(BrowserError::Unavailable);
        }
        let (reply, response) = oneshot::channel();
        let stop = Arc::clone(&self.owner.stop);
        let job = Box::new(move |store: &mut S| {
            // The worker checks expiry independently of the caller's timer: a
            // queued future may stay alive without ever being polled again.
            if stop.load(Ordering::Acquire) || reply.is_closed() || Instant::now() >= deadline {
                return;
            }
            let result = operation(store);
            // The call may already have mutated PostgreSQL. Report an expired
            // result as unavailable, without retrying it or issuing compensation.
            let result = if Instant::now() >= deadline {
                Err(BrowserError::Unavailable)
            } else {
                result
            };
            let _ = reply.send(result);
        });
        let admitted = self.owner.sender.try_send(job);
        // Shutdown can race with admission. In that case the reply closes here;
        // the worker's start checks also prevent the queued command from running.
        if self.owner.stop.load(Ordering::Acquire) {
            return Err(BrowserError::Unavailable);
        }
        admitted.map_err(|error| match error {
            TrySendError::Full(_) => BrowserError::RateLimited,
            TrySendError::Disconnected(_) => BrowserError::Unavailable,
        })?;
        let result = tokio::time::timeout_at(deadline.into(), response)
            .await
            .map_err(|_| BrowserError::Unavailable)?
            .map_err(|_| BrowserError::Unavailable)?;
        // timeout_at polls its inner future first. Do not accept a buffered late
        // reply when a stalled runtime only polls this request after its deadline.
        if Instant::now() >= deadline {
            return Err(BrowserError::Unavailable);
        }
        result
    }

    async fn shutdown(&self) -> Result<(), BrowserError> {
        self.owner.stop.store(true, Ordering::Release);
        let deadline = Instant::now() + SHUTDOWN_DEADLINE;
        let mut done = self.owner.done.clone();
        let result = tokio::time::timeout_at(deadline.into(), async {
            loop {
                // Drop the watch borrow before awaiting. Retained state and
                // changed() cover completion both before and during registration.
                let completed = *done.borrow_and_update();
                if completed {
                    return Ok(());
                }
                done.changed()
                    .await
                    .map_err(|_| BrowserError::Unavailable)?;
            }
        })
        .await
        .map_err(|_| BrowserError::Unavailable)?;
        // A ready completion can beat timeout_at's timer after a late poll.
        // Keep the original wait's deadline even though a NEW shutdown call may
        // now report idempotent success because cleanup has actually finished.
        if Instant::now() >= deadline {
            return Err(BrowserError::Unavailable);
        }
        result
    }
}

#[cfg(test)]
mod component_support;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod scheduling_tests;
