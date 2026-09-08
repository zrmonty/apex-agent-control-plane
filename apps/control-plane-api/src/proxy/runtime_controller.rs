//! Root-owned bounded physical workers. PostgreSQL never runs on Tokio workers.
use super::runtime_client::{RuntimeExecutionClient, RuntimeExecutionConfig, unavailable};
use crate::{ExactScope, PostgresProxyStore, ProxyError, ProxyId, proto};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod health;

const CAPACITY: usize = 8;
const JOB_LIMIT: Duration = Duration::from_secs(150);
const LEASE_TTL: Duration = Duration::from_secs(180);
const TICK: Duration = Duration::from_millis(250);

pub struct RuntimeExecutionOwner {
    config: RuntimeExecutionConfig,
    database: Zeroizing<String>,
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    attempted: bool,
}

struct Shared {
    stopped: AtomicBool,
    active: AtomicBool,
    scan_ok: AtomicBool,
    in_flight: Mutex<BTreeSet<(String, String, String)>>,
    last_response: Mutex<Option<Instant>>,
}

impl Shared {
    fn reserve(&self, key: (String, String, String)) -> Result<bool, ProxyError> {
        let mut active = self.in_flight.lock().map_err(|_| unavailable())?;
        Ok(!self.stopped.load(Ordering::Acquire) && active.len() < CAPACITY && active.insert(key))
    }
}

#[derive(Clone)]
pub struct RuntimeExecutionStatus(Arc<Shared>);
impl RuntimeExecutionStatus {
    pub fn activate(&self) {
        self.0.active.store(true, Ordering::Release);
    }
    pub fn request_shutdown(&self) {
        self.0.stopped.store(true, Ordering::Release);
    }
    pub fn healthy(&self) -> bool {
        !self.0.stopped.load(Ordering::Acquire)
            && self.0.scan_ok.load(Ordering::Acquire)
            && self
                .0
                .last_response
                .lock()
                .ok()
                .is_some_and(|last| last.is_some_and(|time| time.elapsed() < LEASE_TTL))
    }
}

impl RuntimeExecutionOwner {
    pub(crate) fn configuration(&self) -> &RuntimeExecutionConfig {
        &self.config
    }
    pub fn new(config: RuntimeExecutionConfig, database: &str) -> Result<Self, ProxyError> {
        if database.is_empty() || tokio::runtime::Handle::try_current().is_ok() {
            return Err(unavailable());
        }
        Ok(Self {
            config,
            database: Zeroizing::new(database.into()),
            shared: Arc::new(Shared {
                stopped: AtomicBool::new(false),
                active: AtomicBool::new(false),
                scan_ok: AtomicBool::new(false),
                in_flight: Mutex::new(BTreeSet::new()),
                last_response: Mutex::new(None),
            }),
            workers: vec![],
            attempted: false,
        })
    }
    pub fn status(&self) -> RuntimeExecutionStatus {
        RuntimeExecutionStatus(Arc::clone(&self.shared))
    }

    /// Every spawned handle is retained before observing initialization. On any
    /// partial error the caller keeps this owner through synchronous shutdown.
    pub fn start(&mut self) -> Result<(), ProxyError> {
        if self.attempted || tokio::runtime::Handle::try_current().is_ok() {
            return Err(unavailable());
        }
        self.attempted = true;
        let (ready, initial) = mpsc::sync_channel(CAPACITY + 1);
        let mut senders = Vec::with_capacity(CAPACITY);
        for index in 0..CAPACITY {
            let (sender, receiver) = mpsc::sync_channel(1);
            senders.push(sender);
            let (shared, config, database, ready) = (
                Arc::clone(&self.shared),
                self.config.clone(),
                self.database.clone(),
                ready.clone(),
            );
            self.workers.push(
                thread::Builder::new()
                    .name(format!("apex-runtime-exec-{index}"))
                    .spawn(move || {
                        let _stop = Stop(Arc::clone(&shared));
                        let result = worker(shared, config, database, receiver, ready);
                        if result.is_err() { /* root observes stopped; no secret diagnostics */ }
                    })
                    .map_err(|_| unavailable())?,
            );
        }
        let (shared, config, database) = (
            Arc::clone(&self.shared),
            self.config.clone(),
            self.database.clone(),
        );
        self.workers.push(
            thread::Builder::new()
                .name("apex-runtime-inventory".into())
                .spawn(move || {
                    let _stop = Stop(Arc::clone(&shared));
                    let _ = inventory(shared, config, database, senders, ready);
                })
                .map_err(|_| unavailable())?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        for _ in 0..=CAPACITY {
            initial
                .recv_timeout(
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(unavailable)?,
                )
                .map_err(|_| unavailable())??;
        }
        Ok(())
    }

    /// Joins real physical workers, including PostgreSQL cleanup. Reporting
    /// deadlines never detach resources or mint replacement worker capacity.
    pub fn shutdown(&mut self) -> Result<(), ProxyError> {
        self.status().request_shutdown();
        let mut failed = false;
        for worker in self.workers.drain(..) {
            failed |= worker.join().is_err();
        }
        if failed { Err(unavailable()) } else { Ok(()) }
    }
}
impl Drop for RuntimeExecutionOwner {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
struct Stop(Arc<Shared>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
    }
}

struct Job {
    scope: ExactScope,
    proxy_id: ProxyId,
    admitted: Instant,
}
fn inventory(
    shared: Arc<Shared>,
    config: RuntimeExecutionConfig,
    database: Zeroizing<String>,
    senders: Vec<mpsc::SyncSender<Job>>,
    ready: mpsc::SyncSender<Result<(), ProxyError>>,
) -> Result<(), ProxyError> {
    let store = PostgresProxyStore::connect(&database)?;
    ready.send(Ok(())).map_err(|_| unavailable())?;
    let mut scope_index = 0;
    let mut cursor = None;
    while !shared.stopped.load(Ordering::Acquire) {
        if !shared.active.load(Ordering::Acquire) {
            thread::sleep(TICK);
            continue;
        }
        config.recheck()?;
        shared.scan_ok.store(false, Ordering::Release);
        let scope = &config.scopes[scope_index];
        let page = match store.runtime_inventory(scope, cursor.as_ref()) {
            Ok(page) => page,
            Err(_) => {
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        shared.scan_ok.store(true, Ordering::Release);
        if page.is_empty() {
            cursor = None;
            scope_index = (scope_index + 1) % config.scopes.len();
            thread::sleep(TICK);
            continue;
        }
        for proxy_id in page {
            if shared.stopped.load(Ordering::Acquire) {
                break;
            }
            cursor = Some(proxy_id.clone());
            let key = (
                scope.workspace_id.clone(),
                scope.namespace_id.clone(),
                proxy_id.to_string(),
            );
            if !shared.reserve(key.clone())? {
                continue;
            }
            let mut job = Job {
                scope: scope.clone(),
                proxy_id,
                admitted: Instant::now(),
            };
            let mut queued = false;
            for sender in &senders {
                match sender.try_send(job) {
                    Ok(()) => {
                        queued = true;
                        break;
                    }
                    Err(mpsc::TrySendError::Full(value)) => job = value,
                    Err(mpsc::TrySendError::Disconnected(_)) => return Err(unavailable()),
                }
            }
            if !queued {
                shared
                    .in_flight
                    .lock()
                    .map_err(|_| unavailable())?
                    .remove(&key);
            }
        }
        thread::sleep(TICK);
    }
    Ok(())
}

fn worker(
    shared: Arc<Shared>,
    config: RuntimeExecutionConfig,
    database: Zeroizing<String>,
    receiver: mpsc::Receiver<Job>,
    ready: mpsc::SyncSender<Result<(), ProxyError>>,
) -> Result<(), ProxyError> {
    let store = PostgresProxyStore::connect(&database)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| unavailable())?;
    ready.send(Ok(())).map_err(|_| unavailable())?;
    while !shared.stopped.load(Ordering::Acquire) {
        let job = match receiver.recv_timeout(TICK) {
            Ok(job) => job,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let key = (
            job.scope.workspace_id.clone(),
            job.scope.namespace_id.clone(),
            job.proxy_id.to_string(),
        );
        let result = run_job(&shared, &config, &store, &runtime, &job);
        shared
            .in_flight
            .lock()
            .map_err(|_| unavailable())?
            .remove(&key);
        if result.is_err() {
            shared.scan_ok.store(false, Ordering::Release);
        }
    }
    // Close channels/TLS runtime and store on this physical owner thread.
    drop(runtime);
    drop(store);
    Ok(())
}

fn run_job(
    shared: &Shared,
    config: &RuntimeExecutionConfig,
    store: &PostgresProxyStore,
    runtime: &tokio::runtime::Runtime,
    job: &Job,
) -> Result<(), ProxyError> {
    let deadline = job.admitted + JOB_LIMIT;
    check(shared, deadline)?;
    config.recheck()?;
    // Local anchor precedes acquisition; never subtract a remote expiry from
    // this host's wall clock. PG admission time can only shorten the budget.
    let lease_anchor = Instant::now();
    let Some(lease) =
        store.lease_proxy_operation(&job.scope, &job.proxy_id, &config.worker_id, LEASE_TTL)?
    else {
        return Ok(());
    };
    let lease_bound = lease_anchor + LEASE_TTL;
    check(shared, deadline.min(lease_bound))?;
    let checkpoint = || check(shared, deadline.min(lease_bound));
    let request = store.prepare_runtime_attempt_checked(&lease, &checkpoint)?;
    check(shared, deadline.min(lease_bound))?;
    config.recheck()?;
    let desired = proto::ProxyDesiredState::try_from(lease.operation.desired_state)
        .map_err(|_| unavailable())?;
    let rpc_deadline = (job.admitted + Duration::from_secs(125))
        .min(deadline)
        .min(lease_bound);
    let mut execution = runtime.block_on(async {
        let mut client = RuntimeExecutionClient::connect(config, rpc_deadline).await?;
        let mut attempt = 0;
        loop {
            check(shared, rpc_deadline)?;
            let result = client.reconcile(&request, desired, rpc_deadline).await;
            if result
                .as_ref()
                .err()
                .is_some_and(|error| retry_allowed(error, attempt, rpc_deadline))
            {
                attempt += 1;
                // Same persisted command, physical CP slot and original budget.
                // Agent's own exact-proxy guard continues to own any prior work.
                tokio::time::sleep(Duration::from_millis(250)).await;
                config.recheck()?;
                continue;
            }
            break result.map(|response| (client, response));
        }
    });
    // Retain the same channel and physical worker through health and every SQL
    // boundary. Selection precedes evidence mutation of lease.operation.
    let consumption = if let Ok((client, response)) = &mut execution {
        health::consume(
            config,
            store,
            runtime,
            client,
            &health::Attempt {
                lease: &lease,
                request: &request,
                response,
                deadline: rpc_deadline,
            },
            &checkpoint,
        )
        .inspect_err(|error| {
            eprintln!("runtime_execution_health_refused code={}", error.code());
        })
    } else {
        Ok(())
    };
    let response = execution.map(|(_, response)| response);
    if let Ok(value) = &response {
        eprintln!(
            "runtime_execution_received state={} code={}",
            value.observed_state, value.error_code
        );
    }
    // Even timeout does not release this slot during following synchronous work.
    check(shared, deadline.min(lease_bound))?;
    config.recheck()?;
    let observed = store
        .observe_runtime_attempt(
            &lease,
            response.as_ref().ok(),
            &config.installation_id,
            &checkpoint,
        )
        .inspect_err(|error| {
            eprintln!(
                "runtime_execution_observation_refused code={}",
                error.code()
            );
        })?;
    eprintln!(
        "runtime_execution_committed state={}",
        observed.observed_state
    );
    if response.is_ok() {
        *shared.last_response.lock().map_err(|_| unavailable())? = Some(Instant::now());
        store.finish_runtime_attempt(&lease)?;
    }
    consumption?;
    response.map(|_| ())
}
fn check(shared: &Shared, deadline: Instant) -> Result<(), ProxyError> {
    if shared.stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(unavailable())
    } else {
        Ok(())
    }
}

fn retry_allowed(error: &ProxyError, attempt: usize, deadline: Instant) -> bool {
    error.code() == "RUNTIME_EXECUTION_RETRYABLE"
        && attempt < 2
        && deadline
            .checked_duration_since(Instant::now())
            .is_some_and(|remaining| remaining > Duration::from_secs(1))
}

#[cfg(test)]
#[path = "runtime_controller_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_controller/health_tests.rs"]
mod health_tests;
