//! Component-only injected backend. This does not establish PostgreSQL safety.

use super::{BrowserError, Worker};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    task::Poll,
    thread::ThreadId,
    time::Duration,
};
use tokio::{runtime::Runtime, sync::oneshot, task::JoinHandle};

#[derive(Debug)]
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

pub(super) struct Probe {
    mutations: Arc<AtomicUsize>,
    dropped: SyncSender<ThreadRecord>,
    // The factory must create this !Send owner on its eventual worker thread.
    _not_send: Rc<()>,
}

impl Probe {
    pub fn mutate(&mut self) -> Result<usize, BrowserError> {
        Ok(self.mutations.fetch_add(1, Ordering::SeqCst) + 1)
    }

    pub fn mutations(&mut self) -> Result<usize, BrowserError> {
        Ok(self.mutations.load(Ordering::SeqCst))
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.dropped.try_send(ThreadRecord::current());
    }
}

pub(super) struct Witness {
    created: Receiver<ThreadRecord>,
    dropped: Receiver<ThreadRecord>,
    mutations: Arc<AtomicUsize>,
}

impl Witness {
    pub fn wait_for_drop(&self) -> ThreadRecord {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let created = self.created.recv_timeout(Duration::from_secs(1)).unwrap();
        let dropped = self
            .dropped
            .recv_timeout(Duration::from_secs(1))
            .expect("component owner must exit without a retained facade");
        assert_eq!(
            created.id, dropped.id,
            "construct/drop must share the worker"
        );
        assert_eq!(created.name.as_deref(), Some("apex-browser-sessions"));
        assert!(!created.in_tokio && !dropped.in_tokio);
        dropped
    }

    pub fn assert_mutations(&self, expected: usize) {
        assert_eq!(self.mutations.load(Ordering::SeqCst), expected);
    }
}

pub(super) fn component_factory() -> (
    impl FnOnce() -> Result<Probe, BrowserError> + Send + 'static,
    Witness,
) {
    let (created, created_rx) = mpsc::sync_channel(1);
    let (dropped, dropped_rx) = mpsc::sync_channel(1);
    let mutations = Arc::new(AtomicUsize::new(0));
    let observed_mutations = Arc::clone(&mutations);
    let factory = move || {
        let probe = Probe {
            mutations,
            dropped,
            _not_send: Rc::new(()),
        };
        created.send(ThreadRecord::current()).unwrap();
        Ok(probe)
    };
    (
        factory,
        Witness {
            created: created_rx,
            dropped: dropped_rx,
            mutations: observed_mutations,
        },
    )
}

pub(super) fn component_worker() -> (Worker<Probe>, Witness) {
    let (factory, witness) = component_factory();
    (Worker::start(factory).unwrap(), witness)
}

pub(super) fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub(super) async fn poll_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|context| {
        assert!(
            future.as_mut().poll(context).is_pending(),
            "request must be waiting"
        );
        Poll::Ready(())
    })
    .await
}

pub(super) struct Release(Option<SyncSender<()>>);

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

pub(super) fn gate() -> (Release, Receiver<()>) {
    let (sender, receiver) = mpsc::sync_channel(1);
    (Release(Some(sender)), receiver)
}

pub(super) fn wait_at_gate(receiver: Receiver<()>) -> Result<(), BrowserError> {
    // Panic/early return by a test releases the gate through its RAII guard.
    receiver
        .recv_timeout(Duration::from_secs(12))
        .map_err(|_| BrowserError::Unavailable)
}

pub(super) async fn stall(
    worker: Worker<Probe>,
) -> (JoinHandle<Result<(), BrowserError>>, Release) {
    let (release, receiver) = gate();
    let (entered, started) = oneshot::channel();
    let task = tokio::spawn(async move {
        worker
            .request(move |_| {
                let _ = entered.send(());
                wait_at_gate(receiver)
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();
    (task, release)
}
