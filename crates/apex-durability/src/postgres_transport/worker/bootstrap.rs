//! Bounded process-owned trust I/O, independent of per-connection runtimes.

use super::WorkerPostgresError;
use std::sync::{OnceLock, mpsc};
use std::time::Instant;
use tokio::sync::oneshot;
use tokio_postgres_rustls::MakeRustlsConnect;

type BootstrapResult = Result<MakeRustlsConnect, WorkerPostgresError>;
type RootsLoader = Box<dyn FnOnce() -> Result<rustls::RootCertStore, ()> + Send>;

struct Request {
    load_roots: RootsLoader,
    deadline: Instant,
    reply: oneshot::Sender<BootstrapResult>,
}

#[derive(Clone)]
pub(super) struct BootstrapIo {
    sender: mpsc::SyncSender<Request>,
}

// Like getaddrinfo, an OS filesystem read cannot reliably be cancelled. One
// process-owned thread plus 16 queued jobs bounds even permanently stalled CA
// reads. No reconnect creates another thread or makes runtime Drop join this
// executor. DNS has its own fixed executor, so trust I/O cannot consume its slot.
static BOOTSTRAP: OnceLock<Result<BootstrapIo, WorkerPostgresError>> = OnceLock::new();

pub(super) fn global_bootstrap() -> Result<&'static BootstrapIo, WorkerPostgresError> {
    BOOTSTRAP
        .get_or_init(|| BootstrapIo::start().map(|(executor, _process_thread)| executor))
        .as_ref()
        .map_err(|_| WorkerPostgresError::Closed)
}

impl BootstrapIo {
    pub(super) fn start() -> Result<(Self, std::thread::JoinHandle<()>), WorkerPostgresError> {
        let (sender, receiver) = mpsc::sync_channel::<Request>(16);
        let thread = std::thread::Builder::new()
            .name("apex-postgres-trust".into())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    if Instant::now() >= request.deadline || request.reply.is_closed() {
                        continue;
                    }
                    // Includes environment/path lookup, metadata, reading, PEM
                    // parsing and TLS configuration: none runs on the caller.
                    let result = (request.load_roots)()
                        .map(|roots| {
                            MakeRustlsConnect::new(
                                rustls::ClientConfig::builder()
                                    .with_root_certificates(roots)
                                    .with_no_client_auth(),
                            )
                        })
                        .map_err(|_| WorkerPostgresError::Closed);
                    if Instant::now() < request.deadline && !request.reply.is_closed() {
                        let _ = request.reply.send(result);
                    }
                }
            })
            .map_err(|_| WorkerPostgresError::Closed)?;
        Ok((Self { sender }, thread))
    }

    pub(super) fn request(
        &self,
        load_roots: impl FnOnce() -> Result<rustls::RootCertStore, ()> + Send + 'static,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<BootstrapResult>, WorkerPostgresError> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Request {
                load_roots: Box::new(load_roots),
                deadline,
                reply,
            })
            .map_err(|_| WorkerPostgresError::Closed)?;
        Ok(receiver)
    }

    pub(super) async fn load(
        &self,
        load_roots: impl FnOnce() -> Result<rustls::RootCertStore, ()> + Send + 'static,
        deadline: Instant,
    ) -> BootstrapResult {
        if Instant::now() >= deadline {
            return Err(WorkerPostgresError::Deadline);
        }
        let result =
            tokio::time::timeout_at(deadline.into(), self.request(load_roots, deadline)?).await;
        // Never let an expired trust result trigger a late network connection.
        if Instant::now() >= deadline {
            return Err(WorkerPostgresError::Deadline);
        }
        result
            .map_err(|_| WorkerPostgresError::Deadline)?
            .map_err(|_| WorkerPostgresError::Closed)?
    }
}
