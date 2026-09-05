//! These component tests use a loopback tonic peer to exercise the real Rust
//! handlers, not TLS/session acceptance. Production construction requires mTLS.
use super::*;
use crate::{
    InMemoryProxyStore, McpProxyService, OperatorCaller, OperatorTokenAuthenticator, ProxyStore,
    StaticOperatorTokenResolver,
};
use axum::http::{HeaderMap, HeaderValue, header};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tonic::transport::{Endpoint, Server, server::TcpIncoming};
use zeroize::Zeroizing;

const TOKEN: &str = "operator-bridge-component-credential";
const ROOT: &str = "/api/apex/v1/McpProxyService/";

struct Peer {
    bridge: ManagementBridge,
    task: tokio::task::JoinHandle<()>,
    store: Arc<InMemoryProxyStore>,
    calls: Arc<AtomicUsize>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    async fn start(timeout: Duration, stall: bool) -> Self {
        let store = Arc::new(InMemoryProxyStore::default());
        let service =
            McpProxyService::from_store(OperatorTokenAuthenticator::new(resolver()), store.clone())
                .with_event_sink(Arc::new(Events));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = proto::mcp_proxy_service_server::McpProxyServiceServer::with_interceptor(
            service,
            move |request: tonic::Request<()>| {
                count.fetch_add(1, Ordering::SeqCst);
                if stall {
                    // Returning a failure lets timeout tests use a separate socket
                    // blackhole below; production tests never inject this interceptor.
                    return Err(tonic::Status::unavailable("provider-secret-marker"));
                }
                let names: Vec<_> = request
                    .metadata()
                    .keys()
                    .filter_map(|key| match key {
                        tonic::metadata::KeyRef::Ascii(key) => Some(key.as_str()),
                        _ => None,
                    })
                    .collect();
                assert!(!names.contains(&"cookie"));
                assert!(!names.contains(&"x-apex-csrf"));
                assert!(!names.contains(&"x-operator-subject"));
                assert_eq!(
                    request.metadata().get("authorization").unwrap(),
                    format!("Bearer {TOKEN}").as_str()
                );
                assert!(request.metadata().get("grpc-timeout").is_some());
                Ok(request)
            },
        );
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = incoming.local_addr().unwrap();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(server)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            bridge: ManagementBridge::from_channel(channel, timeout, 1),
            task,
            store,
            calls,
        }
    }
}

struct Events;
impl crate::ProxyEventSink for Events {
    fn emit(&self, _: crate::ProxyLifecycleEvent) -> Result<(), crate::ProxyError> {
        Ok(())
    }
}

fn resolver() -> StaticOperatorTokenResolver {
    StaticOperatorTokenResolver::new().with_token(
        TOKEN,
        OperatorCaller::scoped("operator:bridge", ["work/ns"]).unwrap(),
    )
}
fn access() -> OperatorAccess {
    OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &resolver()).unwrap()
}
fn decode(method: &str, body: &[u8]) -> ManagementRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer attacker"),
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("provider-secret-marker"),
    );
    headers.insert("x-operator-subject", HeaderValue::from_static("admin"));
    ManagementRequest::decode(&format!("{ROOT}{method}"), &headers, body).unwrap()
}

#[tokio::test]
async fn forwards_operator_not_browser_headers_and_existing_handler_still_denies_scope() {
    let peer = Peer::start(Duration::from_secs(2), false).await;
    let request = decode(
        "ListProxies",
        br#"{"workspaceId":"work","namespaceId":"ns"}"#,
    );
    assert_eq!(
        peer.bridge.forward(request, &access()).await.unwrap(),
        b"{}"
    );
    let id = uuid::Uuid::now_v7().to_string();
    let proxy = uuid::Uuid::now_v7().to_string();
    let request=decode("CreateProxy", format!(r#"{{"requestId":"{id}","workspaceId":"other","namespaceId":"ns","proxyId":"{proxy}","displayName":"denied","slug":"denied"}}"#).as_bytes());
    assert_eq!(
        peer.bridge.forward(request, &access()).await,
        Err(BrowserError::Forbidden)
    );
    assert!(
        peer.store
            .get(
                crate::ExactScope {
                    workspace_id: "other".into(),
                    namespace_id: "ns".into()
                },
                crate::ProxyId::new(proxy).unwrap()
            )
            .is_err()
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn typed_mutation_keeps_request_id_and_replays_existing_idempotent_result() {
    let peer = Peer::start(Duration::from_secs(2), false).await;
    let id = uuid::Uuid::now_v7().to_string();
    let proxy = uuid::Uuid::now_v7().to_string();
    let body = format!(
        r#"{{"requestId":"{id}","workspaceId":"work","namespaceId":"ns","proxyId":"{proxy}","displayName":"Created","slug":"created"}}"#
    );
    let first = peer
        .bridge
        .forward(decode("CreateProxy", body.as_bytes()), &access())
        .await
        .unwrap();
    let second = peer
        .bridge
        .forward(decode("CreateProxy", body.as_bytes()), &access())
        .await
        .unwrap();
    let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
    assert_eq!(first["proxy"]["proxyId"], proxy);
    assert_eq!(first["proxy"], second["proxy"]);
    assert_eq!(second["duplicate"], true);
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unimplemented_capability_and_unavailable_upstream_stay_visible_without_retry() {
    let peer = Peer::start(Duration::from_secs(2), false).await;
    assert_eq!(
        peer.bridge
            .forward(decode("GetProxyCapabilities", b"{}"), &access())
            .await,
        Err(BrowserError::CapabilityUnavailable)
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    let unavailable = Peer::start(Duration::from_secs(2), true).await;
    assert_eq!(
        unavailable
            .bridge
            .forward(decode("ListProxies", b"{}"), &access())
            .await,
        Err(BrowserError::Unavailable)
    );
    assert_eq!(unavailable.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn channel_readiness_is_inside_deadline_and_admission_is_shared_without_queueing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let channel = Endpoint::from_shared(format!("http://{}", listener.local_addr().unwrap()))
        .unwrap()
        .connect_lazy();
    let bridge = ManagementBridge::from_channel(channel, Duration::from_millis(100), 1);
    let other = bridge.clone();
    let first =
        tokio::spawn(async move { other.forward(decode("ListProxies", b"{}"), &access()).await });
    // Acceptance proves the first call is doing network I/O while holding its permit.
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bridge
            .forward(decode("ListProxies", b"{}"), &access())
            .await,
        Err(BrowserError::RateLimited)
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), first)
            .await
            .unwrap()
            .unwrap(),
        Err(BrowserError::Unavailable)
    );
    // Timeout released admission; a subsequent attempt reaches its own deadline.
    assert_eq!(
        bridge
            .forward(decode("ListProxies", b"{}"), &access())
            .await,
        Err(BrowserError::Unavailable)
    );
}
