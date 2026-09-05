//! Disposable HTTPS wire peer, not a real IdP or session-acceptance fixture.
//! All sockets/tasks are owned by a guard; no process-global environment edits.
use super::super::config::{OidcConfig, tests::config};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oauth2::{HttpRequest, http::Request};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

pub(super) const JSON: &[u8] = br#"{"ok":true}"#;
pub(super) const FORM: &[u8] = b"grant_type=refresh_token&refresh_token=fixture-refresh-canary";

pub(super) fn pki(name: &str, file: &str) -> PathBuf {
    let root = std::env::var_os("APEX_BROWSER_TEST_PKI_DIR")
        .expect("APEX_BROWSER_TEST_PKI_DIR is required; generate the disposable browser PKI first");
    PathBuf::from(root).join(name).join(file)
}

pub(super) fn fixture_config(address: SocketAddr) -> OidcConfig {
    let mut value = config();
    let base = format!("https://{address}/realms/apex");
    value.issuer = base.clone();
    value.authorization_endpoint = format!("{base}/auth");
    value.token_endpoint = format!("{base}/token");
    value.jwks_uri = format!("{base}/certs");
    value.revocation_endpoint = format!("{base}/revoke");
    value.provider_ca_pem = std::fs::read(pki("trusted-host", "ca.pem")).unwrap();
    value
}

pub(super) fn post(uri: &str) -> HttpRequest {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "authorization",
            format!(
                "Basic {}",
                STANDARD.encode(b"apex-browser:fixture-confidential-client-secret")
            ),
        )
        .body(FORM.to_vec())
        .unwrap()
}

pub(super) async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(7), future)
        .await
        .expect("component operation exceeded the independent seven-second watchdog")
}

pub(super) struct Reply {
    pub pieces: Vec<(Duration, Vec<u8>)>,
    pub hold_open: bool,
}

impl Reply {
    pub fn wire(bytes: Vec<u8>) -> Self {
        Self {
            pieces: vec![(Duration::ZERO, bytes)],
            hold_open: false,
        }
    }

    pub fn json(status: u16, body: &[u8]) -> Self {
        Self::wire(response(status, Some("application/json"), body))
    }

    pub fn stall() -> Self {
        Self {
            pieces: Vec::new(),
            hold_open: true,
        }
    }

    pub fn close() -> Self {
        Self {
            pieces: Vec::new(),
            hold_open: false,
        }
    }
}

pub(super) fn response(status: u16, content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(content_type) = content_type {
        bytes.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    bytes.push_str("\r\n");
    let mut bytes = bytes.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn chunked(body: &[u8], extra_headers: &str, terminate: bool) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n{extra_headers}\r\n").into_bytes();
    for chunk in body.chunks(4096) {
        wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        wire.extend_from_slice(chunk);
        wire.extend_from_slice(b"\r\n");
    }
    if terminate {
        wire.extend_from_slice(b"0\r\n\r\n");
    }
    wire
}

#[derive(Clone)]
pub(super) struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        let values: Vec<_> = self.headers.iter().filter(|(key, _)| key == name).collect();
        assert!(values.len() <= 1, "duplicate outbound {name}");
        values.first().map(|(_, value)| value.as_str())
    }
}

struct State {
    connections: AtomicUsize,
    written_responses: AtomicUsize,
    requests: Mutex<Vec<Recorded>>,
    replies: Mutex<VecDeque<Reply>>,
    changed: Notify,
}

pub(super) struct Peer {
    pub address: SocketAddr,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl Peer {
    pub async fn start(replies: Vec<Reply>) -> Self {
        Self::start_at("127.0.0.1", "trusted-host", replies).await
    }

    pub async fn start_at(ip: &str, identity: &str, replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cert =
            CertificateDer::from_pem_file(pki(identity, "control-plane-server.pem")).unwrap();
        let key = PrivateKeyDer::from_pem_file(pki(identity, "control-plane-server.key")).unwrap();
        // The provider peer authenticates its server certificate only. Browser
        // management mTLS is a separate fixture, not weakened by this IdP peer.
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let state = Arc::new(State {
            connections: AtomicUsize::new(0),
            written_responses: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
            changed: Notify::new(),
        });
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        if shared.connections.fetch_add(1, Ordering::SeqCst) >= 64 { break; }
                        let acceptor = acceptor.clone();
                        let shared = Arc::clone(&shared);
                        children.spawn(async move {
                            // Negative TLS cases and cancellation intentionally close sockets.
                            let _ = tokio::time::timeout(Duration::from_secs(12), serve(socket, acceptor, shared)).await;
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    pub fn config(&self) -> OidcConfig {
        fixture_config(self.address)
    }
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
    pub fn requests(&self) -> Vec<Recorded> {
        self.state.requests.lock().unwrap().clone()
    }

    pub async fn wait_requests(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.state.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.requests.lock().unwrap().len() >= count {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("HTTPS peer did not observe the expected request count");
    }

    pub async fn wait_written_responses(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.state.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.written_responses.load(Ordering::SeqCst) >= count {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("HTTPS peer did not flush the expected response bytes");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(socket: TcpStream, acceptor: TlsAcceptor, state: Arc<State>) -> io::Result<()> {
    let mut socket = acceptor.accept(socket).await?;
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        let mut buf = [0; 2048];
        let count = socket.read(&mut buf).await?;
        if count == 0 || bytes.len() + count > 32768 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(&buf[..count]);
    };
    let text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .map_err(|_| io::ErrorKind::InvalidData)?
        .unwrap_or(0);
    if length > 32768 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    while bytes.len() - header_end < length {
        let mut buf = [0; 2048];
        let count = socket.read(&mut buf).await?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&buf[..count]);
    }
    state.requests.lock().unwrap().push(Recorded {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + length].to_vec(),
    });
    state.changed.notify_waiters();
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| Reply::json(200, JSON));
    for (delay, bytes) in reply.pieces {
        tokio::time::sleep(delay).await;
        socket.write_all(&bytes).await?;
        socket.flush().await?;
    }
    state.written_responses.fetch_add(1, Ordering::SeqCst);
    state.changed.notify_waiters();
    if reply.hold_open {
        std::future::pending::<()>().await;
    }
    socket.shutdown().await
}

pub(super) struct Blackhole {
    pub address: SocketAddr,
    hello: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Blackhole {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hello = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&hello);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 5];
            if socket.read_exact(&mut prefix).await.is_ok() {
                shared.lock().unwrap().extend_from_slice(&prefix);
            }
            std::future::pending::<()>().await;
        });
        Self {
            address,
            hello,
            task,
        }
    }

    pub fn assert_client_hello(&self) {
        let prefix = self.hello.lock().unwrap();
        assert_eq!(prefix.len(), 5, "blackhole never received a TLS record");
        assert_eq!(
            &prefix[..2],
            &[0x16, 0x03],
            "expected a TLS handshake record"
        );
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.task.abort();
    }
}
