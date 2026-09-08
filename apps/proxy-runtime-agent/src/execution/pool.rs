//! Eight process-owned physical workers; request cancellation never drops ownership.
use super::reservation::{Guard as ProxyGuard, Kind};
use super::{engine::Engine, journal::Journal, provision};
use crate::{
    authority::RuntimeAuthorityClient, config::ExecutionConfig, owner, proto,
    secrets::StagingOwner, signature::SignatureVerifier,
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tonic::{Request, Status};
pub(crate) const JOB_BUDGET: Duration = Duration::from_secs(120);
mod health;
mod network_readiness;
enum Work {
    Reconcile(Job),
    Inspect(network_readiness::Job),
    Health(health::Job),
}
pub(crate) struct Resources {
    #[cfg(test)]
    pub(crate) hooks: Arc<super::testing::Hooks>,
    pub(super) journal: Journal,
    pub(super) engine: Engine,
    pub(super) staging: StagingOwner,
    pub(super) signature: SignatureVerifier,
    pub(super) network_effect: Mutex<()>,
}
impl Resources {
    pub(crate) fn open(c: &ExecutionConfig, installation: &str) -> Result<Self, &'static str> {
        c.validate()?;
        Ok(Self {
            network_effect: Mutex::new(()),
            #[cfg(test)]
            hooks: Arc::default(),
            journal: Journal::open(&c.journal_root)?,
            engine: Engine::open(c, installation)?,
            staging: StagingOwner::open(&c.staging_root, &c.material_root)
                .map_err(|_| "RUNTIME_STAGING_CONFIG_INVALID")?,
            signature: SignatureVerifier::open(&c.cosign_executable, &c.cosign_cache_root)
                .map_err(|_| "RUNTIME_SIGNATURE_CONFIG_INVALID")?,
        })
    }
}
pub(super) struct Context {
    pub resources: Resources,
    pub authority: Arc<RuntimeAuthorityClient>,
    pub shared: owner::Shared,
    pub runtime: tokio::runtime::Handle,
    pub installation: String,
    pub shutdown: watch::Receiver<bool>,
}
pub(super) struct Job {
    pub request: Request<proto::RuntimeReconcileRequest>,
    pub cancelled: Arc<AtomicBool>,
    pub started: Instant,
    pub desired: AtomicI32,
    pub lease_deadline: Mutex<Option<Instant>>,
    reply: oneshot::Sender<Result<proto::RuntimeReconcileResponse, Status>>,
    _permit: OwnedSemaphorePermit,
    _proxy: ProxyGuard,
}
struct Cancellation(Arc<AtomicBool>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
pub(crate) struct Facility {
    sender: Option<mpsc::SyncSender<Work>>,
    threads: Vec<JoinHandle<()>>,
    slots: Arc<Semaphore>,
    active: Arc<Mutex<BTreeSet<String>>>,
    installation: String,
}
impl Facility {
    pub(crate) fn start(
        resources: Resources,
        authority: Arc<RuntimeAuthorityClient>,
        shared: owner::Shared,
        installation: String,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self, &'static str> {
        let context = Arc::new(Context {
            resources,
            authority,
            shared,
            runtime: tokio::runtime::Handle::current(),
            installation: installation.clone(),
            shutdown,
        });
        let (sender, receiver) = mpsc::sync_channel::<Work>(8);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut facility = Self {
            sender: Some(sender),
            threads: Vec::with_capacity(8),
            slots: Arc::new(Semaphore::new(8)),
            active: Arc::new(Mutex::new(BTreeSet::new())),
            installation,
        };
        for n in 0..8 {
            let receiver = Arc::clone(&receiver);
            let context = Arc::clone(&context);
            let thread = std::thread::Builder::new()
                .name(format!("runtime-effect-{n}"))
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(r) => r.recv(),
                            Err(_) => break,
                        };
                        let Ok(job) = job else {
                            break;
                        };
                        let job = match job {
                            Work::Reconcile(job) => job,
                            Work::Inspect(job) => {
                                network_readiness::run(&context, job);
                                continue;
                            }
                            Work::Health(job) => {
                                health::run(&context, job);
                                continue;
                            }
                        };
                        let result = provision::run(&context, &job).map_err(Status::unavailable);
                        let Job {
                            reply,
                            _permit,
                            _proxy,
                            ..
                        } = job;
                        // Release only after physical work/reaping, but before publishing completion.
                        drop(_proxy);
                        drop(_permit);
                        let _ = reply.send(result);
                    }
                })
                .map_err(|_| "RUNTIME_WORKER_UNAVAILABLE")?;
            facility.threads.push(thread);
        }
        Ok(facility)
    }
    pub(crate) async fn execute(
        &self,
        request: Request<proto::RuntimeReconcileRequest>,
    ) -> Result<proto::RuntimeReconcileResponse, Status> {
        crate::service::validation::request(request.get_ref())?;
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        let key = Journal::key(
            &self.installation,
            request
                .get_ref()
                .target
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("RUNTIME_REQUEST_INVALID"))?,
        );
        let proxy = ProxyGuard::acquire(&self.active, key, Kind::Reconcile)
            .map_err(Status::resource_exhausted)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancellation(Arc::clone(&cancelled));
        let (reply, response) = oneshot::channel();
        let job = Job {
            request,
            cancelled,
            started: Instant::now(),
            desired: AtomicI32::new(0),
            lease_deadline: Mutex::new(None),
            reply,
            _permit: permit,
            _proxy: proxy,
        };
        self.sender
            .as_ref()
            .ok_or_else(|| Status::unavailable("RUNTIME_SHUTTING_DOWN"))?
            .try_send(Work::Reconcile(job))
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        tokio::time::timeout(JOB_BUDGET, response)
            .await
            .map_err(|_| Status::deadline_exceeded("RUNTIME_DEADLINE"))?
            .map_err(|_| Status::unavailable("RUNTIME_WORKER_UNAVAILABLE"))?
    }
}
impl Drop for Facility {
    fn drop(&mut self) {
        self.sender.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
#[cfg(test)]
pub(in crate::execution) mod tests;
