//! Process-owned, fixed-capacity executor for uncancellable OS DNS lookups.

use super::WorkerPostgresError;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{OnceLock, mpsc};
use std::time::Instant;

type LookupResult = Result<Vec<IpAddr>, WorkerPostgresError>;
type LookupReply = tokio::sync::oneshot::Receiver<LookupResult>;

struct LookupRequest {
    host: String,
    deadline: Instant,
    reply: tokio::sync::oneshot::Sender<LookupResult>,
}

pub(super) struct Resolver {
    sender: mpsc::SyncSender<LookupRequest>,
}

// OS getaddrinfo cannot be cancelled. One process-owned thread and at most 16
// queued hostnames bound its resource use. It never belongs to a Tokio runtime,
// so callers and runtime teardown do not wait for an expired OS lookup. Expired
// or cancelled requests never trigger another lookup or a PostgreSQL connection.
static RESOLVER: OnceLock<Result<Resolver, WorkerPostgresError>> = OnceLock::new();

pub(super) fn global_resolver() -> Result<&'static Resolver, WorkerPostgresError> {
    RESOLVER
        .get_or_init(|| {
            start_resolver(|host| {
                (host, 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.take(32).map(|address| address.ip()).collect())
            })
            .map(|(resolver, _process_thread)| resolver)
        })
        .as_ref()
        .map_err(|_| WorkerPostgresError::Closed)
}

impl Resolver {
    pub(super) fn request(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<LookupReply, WorkerPostgresError> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(LookupRequest {
                host: host.to_owned(),
                deadline,
                reply,
            })
            .map_err(|_| WorkerPostgresError::Closed)?;
        Ok(receiver)
    }

    pub(super) async fn lookup(&self, host: &str, deadline: Instant) -> LookupResult {
        let reply = self.request(host, deadline)?;
        let result = tokio::time::timeout_at(deadline.into(), reply).await;
        if Instant::now() >= deadline {
            return Err(WorkerPostgresError::Deadline);
        }
        result
            .map_err(|_| WorkerPostgresError::Deadline)?
            .map_err(|_| WorkerPostgresError::Closed)?
    }
}

pub(super) fn start_resolver(
    mut lookup: impl FnMut(&str) -> std::io::Result<Vec<IpAddr>> + Send + 'static,
) -> Result<(Resolver, std::thread::JoinHandle<()>), WorkerPostgresError> {
    let (sender, receiver) = mpsc::sync_channel::<LookupRequest>(16);
    let thread = std::thread::Builder::new()
        .name("apex-postgres-dns".into())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                if Instant::now() >= request.deadline || request.reply.is_closed() {
                    continue;
                }
                let result = lookup(&request.host).map_err(|_| WorkerPostgresError::Closed);
                if Instant::now() < request.deadline && !request.reply.is_closed() {
                    let _ = request.reply.send(result);
                }
            }
        })
        .map_err(|_| WorkerPostgresError::Closed)?;
    Ok((Resolver { sender }, thread))
}
