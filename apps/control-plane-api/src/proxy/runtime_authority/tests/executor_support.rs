//! Private scheduling fixtures only. No PostgreSQL, TLS, or OS-I/O evidence.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::{Arc, mpsc},
    task::Poll,
    thread::ThreadId,
    time::{Duration, Instant},
};

use super::super::{
    RuntimeAuthorityError,
    executor::{Backend, Client, Lookup},
    lifecycle::{Shared, StopOnExit},
    owner::Workers,
    refresh::Reader,
    request::RequestClaims,
};
use super::support::{bytes, enrollment, peer_policy, request};
use crate::proxy::ProxyError;

pub(super) const OBSERVE: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ThreadRecord {
    pub id: ThreadId,
    pub name: Option<String>,
    pub in_tokio: bool,
}

impl ThreadRecord {
    pub fn current() -> Self {
        Self {
            id: std::thread::current().id(),
            name: std::thread::current().name().map(str::to_owned),
            in_tokio: tokio::runtime::Handle::try_current().is_ok(),
        }
    }
}

pub(super) struct Release(Option<mpsc::SyncSender<()>>);

impl Release {
    pub fn release(mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}

pub(super) fn gate() -> (Release, mpsc::Receiver<()>) {
    let (sender, receiver) = mpsc::sync_channel(1);
    (Release(Some(sender)), receiver)
}

pub(super) fn wait_gate(receiver: mpsc::Receiver<()>) {
    receiver
        .recv_timeout(Duration::from_secs(4))
        .expect("component gate released");
}

#[derive(Debug)]
pub(super) struct Step {
    pub entered: mpsc::SyncSender<ThreadRecord>,
    pub release: Option<mpsc::Receiver<()>>,
    pub after_checkpoint: mpsc::SyncSender<()>,
    pub fail_query: bool,
}

pub(super) struct Probe {
    steps: mpsc::Receiver<Step>,
    dropped: mpsc::SyncSender<ThreadRecord>,
    // Compile-time ownership control: the backend itself cannot cross threads.
    _not_send: Rc<()>,
}

impl Backend for Probe {
    type Snapshot = ThreadRecord;

    fn read_current(
        &mut self,
        _lookup: &Lookup,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Self::Snapshot, ProxyError> {
        check()?;
        let step = self
            .steps
            .recv_timeout(OBSERVE)
            .expect("explicit component step");
        let _ = step.entered.try_send(ThreadRecord::current());
        if let Some(release) = step.release {
            wait_gate(release);
        }
        if step.fail_query {
            // Simulate a transport error returning before another cooperative
            // checkpoint; executor/handler must still recheck all refusals.
            return Err(ProxyError::new(
                "PROXY_STORE_UNAVAILABLE",
                "PRIVATE-QUERY-CANARY",
            ));
        }
        // Models the boundary between queries, not physical query cancellation.
        check()?;
        let _ = step.after_checkpoint.try_send(());
        Ok(ThreadRecord::current())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.dropped.try_send(ThreadRecord::current());
    }
}

pub(super) struct Witness {
    pub created: mpsc::Receiver<ThreadRecord>,
    pub dropped: mpsc::Receiver<ThreadRecord>,
    steps: mpsc::SyncSender<Step>,
}

pub(super) struct Progress {
    pub entered: mpsc::Receiver<ThreadRecord>,
    pub after_checkpoint: mpsc::Receiver<()>,
}

impl Witness {
    pub fn step(&self, release: Option<mpsc::Receiver<()>>) -> Progress {
        self.step_with(release, false)
    }

    pub fn failing_step(&self, release: Option<mpsc::Receiver<()>>) -> Progress {
        self.step_with(release, true)
    }

    fn step_with(&self, release: Option<mpsc::Receiver<()>>, fail_query: bool) -> Progress {
        let (entered, entered_rx) = mpsc::sync_channel(1);
        let (after_checkpoint, after_rx) = mpsc::sync_channel(1);
        self.steps
            .try_send(Step {
                entered,
                release,
                after_checkpoint,
                fail_query,
            })
            .unwrap();
        Progress {
            entered: entered_rx,
            after_checkpoint: after_rx,
        }
    }
}

pub(super) fn backend() -> (
    impl FnOnce() -> Result<Probe, RuntimeAuthorityError> + Send + 'static,
    Witness,
) {
    let (created, created_rx) = mpsc::sync_channel(1);
    let (dropped, dropped_rx) = mpsc::sync_channel(1);
    let (steps, steps_rx) = mpsc::sync_channel(16);
    (
        move || {
            let probe = Probe {
                steps: steps_rx,
                dropped,
                _not_send: Rc::new(()),
            };
            created.send(ThreadRecord::current()).unwrap();
            Ok(probe)
        },
        Witness {
            created: created_rx,
            dropped: dropped_rx,
            steps,
        },
    )
}

pub(super) fn publish(shared: &Shared, version: &str) {
    let (mut peer, mut enrollment) = (peer_policy(), enrollment());
    for value in [&mut peer, &mut enrollment] {
        value["validFromUnixUs"] = "1".into();
        value["expiresAtUnixUs"] = u64::MAX.to_string().into();
    }
    enrollment["version"] = version.into();
    let now = Instant::now();
    shared
        .policy
        .lock()
        .unwrap()
        .publish(&bytes(&peer), &bytes(&enrollment), now, now)
        .unwrap();
}

pub(super) fn reader(shared: Arc<Shared>) -> Result<Reader, RuntimeAuthorityError> {
    reader_with(shared, None, None)
}

pub(super) fn reader_with(
    shared: Arc<Shared>,
    before_ready: Option<mpsc::Receiver<()>>,
    before_exit: Option<mpsc::Receiver<()>>,
) -> Result<Reader, RuntimeAuthorityError> {
    let (ready, initial) = mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("apex-runtime-policy".into())
        .spawn(move || {
            let _stop = StopOnExit(Arc::clone(&shared));
            if let Some(gate) = before_ready {
                wait_gate(gate);
            }
            if shared.stopped() {
                return;
            }
            publish(&shared, "enrollment-1");
            if ready.send(Ok(())).is_err() {
                return;
            }
            while !shared.stopped() {
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some(gate) = before_exit {
                wait_gate(gate);
            }
        })
        .map_err(|_| RuntimeAuthorityError::Unavailable)?;
    Ok(Reader { handle, initial })
}

pub(super) fn lookup(shared: &Shared, budget: Duration) -> Lookup {
    let mut claims = RequestClaims::parse(&request()).unwrap();
    claims.budget = budget;
    Lookup {
        claims,
        selected: shared
            .current()
            .expect("otherwise-current component metadata"),
        worker_id: "worker-a".into(),
        started: Instant::now(),
    }
}

pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub(super) async fn poll_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|context| {
        assert!(
            future.as_mut().poll(context).is_pending(),
            "request must await owned work"
        );
        Poll::Ready(())
    })
    .await
}

pub(super) struct Running {
    pub owner: Owned,
    pub client: Client<ThreadRecord>,
    pub witness: Witness,
}

// Keep the same real owner available for cleanup on both assertion failure and
// normal exit. Production Drop only signals; tests explicitly observe joins.
pub(super) struct Owned(pub Workers);

impl Owned {
    pub fn new() -> Self {
        Self(Workers::new())
    }
}

impl std::ops::Deref for Owned {
    type Target = Workers;
    fn deref(&self) -> &Workers {
        &self.0
    }
}

impl std::ops::DerefMut for Owned {
    fn deref_mut(&mut self) -> &mut Workers {
        &mut self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let result = self.0.shutdown(OBSERVE);
        if !std::thread::panicking() {
            assert!(result.cleanup_complete);
        }
    }
}

impl Running {
    pub fn start() -> Self {
        let (factory, witness) = backend();
        let mut owner = Owned::new();
        let client = owner
            .start(reader, factory, OBSERVE)
            .expect("component factory plus initial metadata must start");
        Self {
            owner,
            client,
            witness,
        }
    }

    pub fn lookup(&self, budget: Duration) -> Lookup {
        lookup(&self.owner.shared, budget)
    }
}

pub(super) fn assert_status<T>(result: Result<T, tonic::Status>, code: tonic::Code, text: &str) {
    let error = match result {
        Ok(_) => panic!("unexpected component success"),
        Err(error) => error,
    };
    assert_eq!(error.code(), code);
    assert_eq!(error.message(), text);
    assert!(error.details().is_empty());
}
