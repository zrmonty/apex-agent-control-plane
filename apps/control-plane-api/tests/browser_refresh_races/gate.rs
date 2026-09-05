//! A transport gate, never an identity provider: forwards genuine HTTPS bytes
//! and can hold/drop exactly one complete successful refresh response.
use super::{fixture::within, support::Pki};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
use zeroize::Zeroizing;

#[path = "held.rs"]
mod held;
#[path = "wire.rs"]
mod wire;
pub use held::HeldReply;

pub const ISSUER: &str = "https://127.0.0.1:18461/realms/apex";
const FRONT: &str = "127.0.0.1:18461";
const BACKEND: &str = "https://127.0.0.1:18462";
const MAX_TASKS: usize = 8;
const MAX_CONNECTIONS: usize = 128;
const CONNECTION_BUDGET: Duration = Duration::from_secs(5);

enum Decision {
    Release,
    Close,
}
struct Shared {
    armed: AtomicBool,
    slot: Mutex<Option<oneshot::Sender<HeldReply>>>,
    refresh_requests: AtomicUsize,
    refresh_responses: AtomicUsize,
    revocations: AtomicUsize,
    failures: AtomicUsize,
}

pub struct RefreshGate {
    shared: Arc<Shared>,
    pub(super) client: reqwest::Client,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

pub struct ArmedReply(oneshot::Receiver<HeldReply>);
impl ArmedReply {
    pub async fn completed(self) -> HeldReply {
        within(self.0)
            .await
            .expect("gate must receive a complete real Keycloak refresh 200")
    }
}

impl RefreshGate {
    pub fn start(pki: &Pki) -> Self {
        apex_control_plane_api::install_rustls_provider();
        let certificate =
            CertificateDer::from_pem_slice(&pki.trusted("control-plane-server.pem")).unwrap();
        let pem = Zeroizing::new(pki.trusted("control-plane-server.key"));
        let key = PrivateKeyDer::from_pem_slice(&pem).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let ca = reqwest::Certificate::from_pem(&pki.trusted("ca.pem")).unwrap();
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only([ca])
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connection_verbose(false)
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(MAX_TASKS)
            .build()
            .unwrap();
        let shared = Arc::new(Shared {
            armed: AtomicBool::new(false),
            slot: Mutex::new(None),
            refresh_requests: AtomicUsize::new(0),
            refresh_responses: AtomicUsize::new(0),
            revocations: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
        });
        let (stop, stopping) = oneshot::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let state = Arc::clone(&shared);
        let backend = client.clone();
        let thread = thread::Builder::new()
            .name("e2-keycloak-gate".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(1)
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::bind(FRONT)
                        .await
                        .expect("E2 owns only HTTPS 127.0.0.1:18461");
                    // Sent inside block_on after binding, never from a parked runtime.
                    if ready.send(()).is_err() {
                        return;
                    }
                    serve(listener, acceptor, backend, state, stopping).await;
                });
            })
            .unwrap();
        // Construct the guard before waiting so startup failure still stops and
        // joins precisely this OS thread; the shared 18451 fixture is untouched.
        let gate = Self {
            shared,
            client,
            stop: Some(stop),
            thread: Some(thread),
        };
        started
            .recv_timeout(Duration::from_secs(2))
            .expect("E2 gate startup watchdog");
        gate
    }

    pub fn hold_next_refresh(&self) -> ArmedReply {
        assert!(
            !self.shared.armed.swap(true, Ordering::SeqCst),
            "one held reply per fixture"
        );
        let (send, receive) = oneshot::channel();
        *self.shared.slot.lock().unwrap() = Some(send);
        ArmedReply(receive)
    }

    pub fn refresh_counts(&self) -> (usize, usize) {
        assert_eq!(
            self.shared.failures.load(Ordering::SeqCst),
            0,
            "gate transport failed"
        );
        (
            self.shared.refresh_requests.load(Ordering::SeqCst),
            self.shared.refresh_responses.load(Ordering::SeqCst),
        )
    }

    pub fn revocations(&self) -> usize {
        self.shared.revocations.load(Ordering::SeqCst)
    }
}

impl Drop for RefreshGate {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let joined = thread.join();
            if !std::thread::panicking() {
                assert!(joined.is_ok(), "E2 gate thread failed");
            }
        }
    }
}

async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    client: reqwest::Client,
    shared: Arc<Shared>,
    mut stopping: oneshot::Receiver<()>,
) {
    let mut tasks = JoinSet::new();
    let mut connections = 0;
    loop {
        tokio::select! {
            biased;
            _ = &mut stopping => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if !matches!(result, Some(Ok(Ok(Ok(()))))) {
                    shared.failures.fetch_add(1, Ordering::SeqCst);
                }
            }
            accepted = listener.accept(), if tasks.len() < MAX_TASKS => {
                let Ok((socket, address)) = accepted else { break; };
                connections += 1;
                if !address.ip().is_loopback() || connections > MAX_CONNECTIONS {
                    shared.failures.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                let acceptor = acceptor.clone();
                let client = client.clone();
                let shared = Arc::clone(&shared);
                tasks.spawn(async move {
                    tokio::time::timeout(CONNECTION_BUDGET, forward(socket, acceptor, client, shared)).await
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn forward(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    client: reqwest::Client,
    shared: Arc<Shared>,
) -> Result<(), &'static str> {
    let mut tls = acceptor
        .accept(socket)
        .await
        .map_err(|_| "gate TLS handshake failed")?;
    let request = wire::read_request(&mut tls).await?;
    let refresh = request.is_refresh();
    let revoke = request.is_revocation();
    let hook = if refresh {
        shared.refresh_requests.fetch_add(1, Ordering::SeqCst);
        shared.slot.lock().unwrap().take()
    } else {
        None
    };
    if revoke {
        shared.revocations.fetch_add(1, Ordering::SeqCst);
    }
    // This fixed URL is the only network destination. No provider URL rewriting,
    // proxy environment, redirects, credential fabrication or automatic retry.
    let response = request.forward(&client).await?;
    let reply = wire::read_reply(response).await?;
    if refresh && reply.status == 200 {
        shared.refresh_responses.fetch_add(1, Ordering::SeqCst);
    }
    if let Some(hook) = hook {
        if reply.status != 200 {
            return Err("expected real refresh 200 after rotation");
        }
        let (decision, decided) = oneshot::channel();
        let held = HeldReply::new(reply.body.clone(), decision, Instant::now());
        if hook.send(held).is_err() {
            return Ok(());
        }
        // Cancellation/unwind/lost response closes downstream without writing
        // headers. Revocation and metadata run on other bounded connection tasks.
        match tokio::time::timeout(Duration::from_secs(3), decided).await {
            Ok(Ok(Decision::Release)) => {}
            Ok(Ok(Decision::Close)) | Ok(Err(_)) => return Ok(()),
            Err(_) => return Err("held reply decision watchdog"),
        }
    }
    reply.write(&mut tls).await
}
