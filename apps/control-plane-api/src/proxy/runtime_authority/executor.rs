//! Private bounded queue; the backend never leaves its owning thread.
//! The generic backend seam is for component scheduling; production uses only PG.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

use super::{
    RuntimeAuthorityError,
    lifecycle::{Shared, check_elapsed},
    policy::SelectedPolicy,
    request::RequestClaims,
};
use crate::proxy::ProxyError;

const QUEUE_CAPACITY: usize = 8;

// Private claims/binding only. Original tonic Request remains in the handler;
// neither a TLS extension nor a manufactured authenticated view is transported.
pub(super) struct Lookup {
    pub claims: RequestClaims,
    pub selected: Arc<SelectedPolicy>,
    pub worker_id: String,
    pub started: Instant,
}

pub(super) trait Backend: 'static {
    type Snapshot: Send + 'static;

    fn read_current(
        &mut self,
        lookup: &Lookup,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Self::Snapshot, ProxyError>;
}

// The facade is parameterized only by the reply, never by the backend owner.
pub(super) struct Client<T> {
    inner: Arc<Facade<T>>,
}

struct Facade<T> {
    sender: SyncSender<Job<T>>,
    shared: Arc<Shared>,
}

pub(super) struct Job<T> {
    pub lookup: Lookup,
    pub reply: oneshot::Sender<Result<T, tonic::Status>>,
    pub cancelled: Arc<AtomicBool>,
    pub shared: Arc<Shared>,
}

pub(super) fn channel<T>(shared: Arc<Shared>) -> (Client<T>, Receiver<Job<T>>) {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
    (
        Client {
            inner: Arc::new(Facade { sender, shared }),
        },
        receiver,
    )
}

impl<T> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Drop for Facade<T> {
    fn drop(&mut self) {
        self.shared.stop();
    }
}

impl<T> fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityClient { [redacted] }")
    }
}

impl<T: Send + 'static> Client<T> {
    pub(super) async fn request(&self, lookup: Lookup) -> Result<T, tonic::Status> {
        let started = lookup.started;
        let budget = lookup.claims.budget;
        let selected = Arc::clone(&lookup.selected);
        let recheck = || {
            check_elapsed(started, budget)?;
            if self.inner.shared.stopped() {
                return Err(RuntimeAuthorityError::Unavailable);
            }
            self.inner.shared.recheck(&selected)
        };
        recheck().map_err(RuntimeAuthorityError::status)?;
        let deadline = started
            .checked_add(budget)
            .ok_or_else(|| RuntimeAuthorityError::Deadline.status())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        // Installed before admission, including queue-full and future-abort paths.
        let _cancel = CancelOnDrop(Arc::clone(&cancelled));
        let (reply, receiver) = oneshot::channel();
        let job = Job {
            lookup,
            reply,
            cancelled,
            shared: Arc::clone(&self.inner.shared),
        };
        self.inner
            .sender
            .try_send(job)
            .map_err(|error| match error {
                TrySendError::Full(_) => RuntimeAuthorityError::Busy.status(),
                TrySendError::Disconnected(_) => RuntimeAuthorityError::Unavailable.status(),
            })?;
        #[cfg(feature = "test-support")]
        self.inner
            .shared
            .observations
            .admitted
            .fetch_add(1, Ordering::Release);
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver).await;
        // A ready buffered reply must not beat an expired timer or changed policy.
        recheck().map_err(RuntimeAuthorityError::status)?;
        result
            .map_err(|_| RuntimeAuthorityError::Deadline.status())?
            .map_err(|_| RuntimeAuthorityError::Unavailable.status())?
    }
}

impl<T> Job<T> {
    pub(super) fn check(&self) -> Result<(), ProxyError> {
        let check = || {
            if self.cancelled.load(Ordering::Acquire) || self.reply.is_closed() {
                return Err(RuntimeAuthorityError::Cancelled);
            }
            check_elapsed(self.lookup.started, self.lookup.claims.budget)?;
            self.shared.recheck(&self.lookup.selected)
        };
        check().map_err(|error| ProxyError::new(error.code(), error.code()))
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) fn run<B: Backend>(
    mut backend: B,
    receiver: Receiver<Job<B::Snapshot>>,
    shared: &Shared,
) {
    while !shared.stopped() {
        let job = match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(job) => job,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        #[cfg(feature = "test-support")]
        shared.observations.visited.fetch_add(1, Ordering::Release);
        let result = job.check().and_then(|()| {
            #[cfg(feature = "test-support")]
            shared
                .observations
                .dispatched
                .fetch_add(1, Ordering::Release);
            backend.read_current(&job.lookup, &|| job.check())
        });
        // This runs after both database success and error, after transaction RAII
        // cleanup, before any reply or subsequent job can be dispatched.
        let result = job.check().and(result).map_err(store_status);
        let _ = job.reply.send(result);
        #[cfg(feature = "test-support")]
        shared.observations.settled.fetch_add(1, Ordering::Release);
    }
}

fn store_status(error: ProxyError) -> tonic::Status {
    use tonic::Code;
    let code = match error.code() {
        "RUNTIME_AUTHORITY_CANCELLED" => Code::Cancelled,
        "RUNTIME_AUTHORITY_DEADLINE" => Code::DeadlineExceeded,
        "RUNTIME_AUTHORITY_POLICY_CHANGED" | "PROXY_RUNTIME_OPERATION_NOT_CURRENT" => {
            Code::FailedPrecondition
        }
        "INVALID_RUNTIME_OPERATION_CLAIMS" => Code::InvalidArgument,
        _ => return RuntimeAuthorityError::Unavailable.status(),
    };
    tonic::Status::new(code, error.code())
}

impl Backend for crate::proxy::PostgresProxyStore {
    type Snapshot = crate::proxy::RuntimeOperationSnapshot;

    fn read_current(
        &mut self,
        lookup: &Lookup,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Self::Snapshot, ProxyError> {
        let message = &lookup.claims.message;
        let target = message.target.as_ref().ok_or_else(|| {
            ProxyError::new(
                "INVALID_RUNTIME_OPERATION_CLAIMS",
                "Invalid runtime claims.",
            )
        })?;
        self.read_current_runtime_operation_checked(
            target,
            &message.operation_id,
            &lookup.worker_id,
            check,
        )
    }
}

impl fmt::Debug for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityLookup { [redacted] }")
    }
}
