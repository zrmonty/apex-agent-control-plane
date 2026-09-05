//! Process-owned DNS workers; caller cancellation cannot cancel OS getaddrinfo.
//! Like the PostgreSQL resolver, these are dedicated OS threads with oneshot
//! replies, not Tokio blocking tasks. Unlike its queue, each worker has exactly
//! one admission slot: no request can wait behind an already admitted lookup.
use crate::browser::errors::BrowserError;
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, OnceLock, mpsc},
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

const WORKERS: usize = 8;
const MAX_ADDRESSES: usize = 32;
// The fixed deployment URL is already bounded to 2048 bytes. Check again before
// copying the host into a job; this does not broaden endpoint authority.
const MAX_HOST_BYTES: usize = 2048;

type LookupResult = Result<Vec<SocketAddr>, BrowserError>;
pub(super) type LookupReply = oneshot::Receiver<LookupResult>;

struct Job {
    host: String,
    deadline: Instant,
    reply: oneshot::Sender<LookupResult>,
    // Ownership moves to the worker, never to the async response future.
    _permit: OwnedSemaphorePermit,
}

struct Worker {
    sender: mpsc::SyncSender<Job>,
    admission: Arc<Semaphore>,
}

#[derive(Clone)]
pub(super) struct Resolver {
    workers: Arc<[Worker]>,
}

// Multiple providers share both threads and admission. If initialization fails,
// fail closed rather than retrying construction of further pools per request.
static RESOLVER: OnceLock<Result<Arc<Resolver>, BrowserError>> = OnceLock::new();

pub(super) fn global_resolver() -> Result<Arc<Resolver>, BrowserError> {
    RESOLVER
        .get_or_init(|| {
            start_resolver(|host| {
                (host, 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.take(MAX_ADDRESSES).collect())
            })
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|_| BrowserError::Unavailable)
}

pub(super) fn start_resolver(
    lookup: impl Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
) -> Result<Arc<Resolver>, BrowserError> {
    let lookup = Arc::new(lookup);
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        // This buffer is a handoff to an idle worker, not an extra queue: its
        // single permit covers the handoff AND the entire running OS lookup.
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let lookup = Arc::clone(&lookup);
        let thread = std::thread::Builder::new()
            .name("apex-oidc-dns".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    if Instant::now() >= job.deadline || job.reply.is_closed() {
                        continue;
                    }
                    let result = lookup(&job.host)
                        .map_err(|_| BrowserError::Unavailable)
                        .and_then(|addresses| {
                            if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
                                Err(BrowserError::Unavailable)
                            } else {
                                Ok(addresses)
                            }
                        });
                    if Instant::now() < job.deadline && !job.reply.is_closed() {
                        let _ = job.reply.send(result);
                    }
                    // The job's permit drops only after lookup has returned,
                    // even if its reply receiver was dropped long before then.
                }
            })
            .map_err(|_| BrowserError::Unavailable)?;
        // Intentionally process-owned: Tokio teardown never joins OS DNS. A
        // non-global test pool exits when its senders drop and jobs finish.
        drop(thread);
        workers.push(Worker {
            sender,
            admission: Arc::new(Semaphore::new(1)),
        });
    }
    Ok(Arc::new(Resolver {
        workers: workers.into(),
    }))
}

impl Resolver {
    pub(super) fn request(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<LookupReply, BrowserError> {
        if Instant::now() >= deadline || host.is_empty() || host.len() > MAX_HOST_BYTES {
            return Err(BrowserError::Unavailable);
        }
        for worker in self.workers.iter() {
            let Ok(permit) = Arc::clone(&worker.admission).try_acquire_owned() else {
                continue;
            };
            if Instant::now() >= deadline {
                return Err(BrowserError::Unavailable);
            }
            let (reply, receiver) = oneshot::channel();
            worker
                .sender
                .try_send(Job {
                    host: host.to_owned(),
                    deadline,
                    reply,
                    _permit: permit,
                })
                .map_err(|_| BrowserError::Unavailable)?;
            return Ok(receiver);
        }
        Err(BrowserError::Unavailable)
    }

    pub(super) async fn lookup(&self, host: &str, deadline: Instant) -> LookupResult {
        let receiver = self.request(host, deadline)?;
        let result = tokio::time::timeout_at(deadline.into(), receiver).await;
        // A ready oneshot can beat timeout_at on a late poll. Wall time remains
        // authoritative even when the worker's successful reply was buffered.
        if Instant::now() >= deadline {
            return Err(BrowserError::Unavailable);
        }
        result
            .map_err(|_| BrowserError::Unavailable)?
            .map_err(|_| BrowserError::Unavailable)?
    }
}

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.clone();
        let deadline = Instant::now().checked_add(super::CONNECT_TIMEOUT);
        Box::pin(async move {
            let deadline = deadline.ok_or(BrowserError::Unavailable)?;
            let addresses = resolver.lookup(name.as_str(), deadline).await?;
            // Return addresses only. Reqwest keeps the original configured URL,
            // Host, TLS SNI/name verification, port and CA policy unchanged.
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
