use super::support::*;
use apex_control_plane_api::{
    InMemoryProxyStore, MAX_CONTROL_REQUEST_BYTES, McpProxyService, OperatorTokenAuthenticator,
    ProxyError, ProxyEventSink, ProxyLifecycleEvent, StaticOperatorTokenResolver,
    browser::{
        errors::BrowserError,
        rpc::{ManagementBridge, ManagementTransportConfig},
    },
    proto::{
        self,
        mcp_proxy_service_server::{McpProxyService as RpcService, McpProxyServiceServer},
    },
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::{Notify, oneshot};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig, server::TcpIncoming},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Mode {
    Real,
    OversizedResponse,
    DelayFirstCreateReply,
}

pub struct State {
    calls: AtomicUsize,
    identities_match: AtomicBool,
    metadata_match: AtomicBool,
    capability_replies: AtomicUsize,
    create_ids: Mutex<Vec<String>>,
    committed_response: Mutex<Option<proto::CreateProxyResponse>>,
    pub committed: Notify,
    release_reply: Notify,
}

impl State {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            identities_match: AtomicBool::new(true),
            metadata_match: AtomicBool::new(true),
            capability_replies: AtomicUsize::new(0),
            create_ids: Mutex::new(Vec::new()),
            committed_response: Mutex::new(None),
            committed: Notify::new(),
            release_reply: Notify::new(),
        }
    }

    pub fn rpc_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn capability_replies(&self) -> usize {
        self.capability_replies.load(Ordering::SeqCst)
    }

    pub fn peer_identity_and_metadata_match(&self) -> bool {
        self.identities_match.load(Ordering::SeqCst) && self.metadata_match.load(Ordering::SeqCst)
    }

    pub fn create_ids(&self) -> Vec<String> {
        self.create_ids.lock().unwrap().clone()
    }

    pub fn committed_response(&self) -> proto::CreateProxyResponse {
        self.committed_response
            .lock()
            .unwrap()
            .clone()
            .expect("real create must have committed")
    }
}

pub struct Peer {
    pub target: String,
    pub state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<TestTask<Result<(), tonic::transport::Error>>>,
}

impl Peer {
    pub async fn start(pki: &Pki, mode: Mode) -> Self {
        apex_control_plane_api::install_rustls_provider();
        let state = Arc::new(State::new());
        let real = McpProxyService::from_store(
            OperatorTokenAuthenticator::new(resolver()),
            Arc::new(InMemoryProxyStore::default()),
        )
        .with_event_sink(Arc::new(ComponentEvents));
        let fixture = Fixture {
            real,
            auth: OperatorTokenAuthenticator::new(resolver()),
            expected_client_der: pki.client_der(),
            state: state.clone(),
            mode,
        };
        let key = Zeroizing::new(pki.trusted("control-plane-server.key"));
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                pki.trusted("control-plane-server.pem"),
                key.as_slice(),
            ))
            .client_ca_root(Certificate::from_pem(pki.trusted("ca.pem")))
            .client_auth_optional(false)
            .timeout(CONNECT_TIMEOUT);
        let mut server = Server::builder()
            .tls_config(tls)
            .expect("fixture TLS must be valid");
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = format!("https://{}", incoming.local_addr().unwrap());
        let service = McpProxyServiceServer::new(fixture)
            .max_decoding_message_size(MAX_CONTROL_REQUEST_BYTES)
            .max_encoding_message_size(TEST_SERVER_MESSAGE_LIMIT);
        let (shutdown, stopping) = oneshot::channel();
        let task = TestTask::spawn(async move {
            server
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
        });
        Self {
            target,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub async fn assert_healthy(&self, pki: &Pki) {
        let bridge = connect(pki, &self.target, RPC_TIMEOUT).await;
        assert_eq!(
            within(bridge.forward(list_request(), &access()))
                .await
                .unwrap(),
            b"{}"
        );
        assert!(self.state.peer_identity_and_metadata_match());
    }

    pub async fn assert_rejected_before_rpc(&self, config: ManagementTransportConfig) {
        let before = self.state.rpc_calls();
        // TLS 1.3 client-certificate refusal can become visible on the first
        // RPC after connect. Either stage must refuse with zero peer dispatch.
        let outcome = within(async {
            let bridge = ManagementBridge::connect(config).await?;
            bridge.forward(list_request(), &access()).await.map(|_| ())
        })
        .await;
        assert!(
            matches!(
                outcome,
                Err(BrowserError::Unavailable | BrowserError::Internal)
            ),
            "invalid TLS configuration must fail at transport, not succeed or reach authorization"
        );
        assert_eq!(
            self.state.rpc_calls(),
            before,
            "rejected TLS must not reach an RPC handler"
        );
    }

    pub async fn shutdown(mut self) {
        self.state.release_reply.notify_waiters();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task
            .take()
            .unwrap()
            .join()
            .await
            .expect("fixture server failed");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.state.release_reply.notify_waiters();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // TestTask aborts the server on panic; no listener survives this owner.
    }
}

/// The real handler requires an event sink. This component acknowledges events
/// locally and makes no durable-evidence or live-session acceptance claim.
struct ComponentEvents;
impl ProxyEventSink for ComponentEvents {
    fn emit(&self, _: ProxyLifecycleEvent) -> Result<(), ProxyError> {
        Ok(())
    }
}

struct Fixture {
    real: McpProxyService<StaticOperatorTokenResolver>,
    auth: OperatorTokenAuthenticator<StaticOperatorTokenResolver>,
    expected_client_der: Vec<u8>,
    state: Arc<State>,
    mode: Mode,
}

impl Fixture {
    fn check<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.state.calls.fetch_add(1, Ordering::SeqCst) >= 32 {
            return Err(Status::resource_exhausted("bounded fixture request budget"));
        }
        let identity_matches = request.peer_certs().is_some_and(|certificates| {
            certificates
                .first()
                .is_some_and(|cert| cert.as_ref() == self.expected_client_der.as_slice())
        });
        self.state
            .identities_match
            .fetch_and(identity_matches, Ordering::SeqCst);
        let metadata = request.metadata();
        let metadata_matches = [
            "cookie",
            "x-apex-csrf",
            "x-operator-subject",
            "x-forwarded-host",
        ]
        .iter()
        .all(|name| !metadata.contains_key(*name))
            && metadata.contains_key("grpc-timeout");
        self.state
            .metadata_match
            .fetch_and(metadata_matches, Ordering::SeqCst);
        if !identity_matches || !metadata_matches {
            return Err(Status::unauthenticated(
                "fixture identity/metadata check failed",
            ));
        }
        self.auth
            .authenticate(metadata)
            .map_err(|_| Status::unauthenticated("fixture operator rejected"))?;
        Ok(())
    }
}

// The macro expands the entire async_trait impl so its delegated methods get
// the same async transformation as the two deliberately fault-injected methods.
macro_rules! delegate_methods {
    ($(($method:ident, $input:ident, $output:ident)),+ $(,)?) => {
        #[tonic::async_trait]
        impl RpcService for Fixture {
            async fn create_proxy(&self, request: Request<proto::CreateProxyRequest>)
                -> Result<Response<proto::CreateProxyResponse>, Status> {
                self.check(&request)?;
                let first = {
                    let mut ids = self.state.create_ids.lock().unwrap();
                    if ids.len() >= 16 {
                        return Err(Status::resource_exhausted("bounded create fixture"));
                    }
                    ids.push(request.get_ref().request_id.clone());
                    ids.len() == 1
                };
                let response = self.real.create_proxy(request).await?;
                if first && matches!(self.mode, Mode::DelayFirstCreateReply) {
                    *self.state.committed_response.lock().unwrap() = Some(response.get_ref().clone());
                    self.state.committed.notify_one();
                    self.state.release_reply.notified().await;
                }
                Ok(response)
            }

            async fn get_proxy_capabilities(&self, request: Request<proto::GetProxyCapabilitiesRequest>)
                -> Result<Response<proto::GetProxyCapabilitiesResponse>, Status> {
                self.check(&request)?;
                if matches!(self.mode, Mode::OversizedResponse) {
                    self.state.capability_replies.fetch_add(1, Ordering::SeqCst);
                    return Ok(Response::new(proto::GetProxyCapabilitiesResponse {
                        supported: vec![],
                        observed_at_unix_us: 9_007_199_254_740_993,
                        contract_version: "x".repeat(MAX_CONTROL_REQUEST_BYTES + 1),
                    }));
                }
                RpcService::get_proxy_capabilities(&self.real, request).await
            }

            $(async fn $method(&self, request: Request<proto::$input>)
                -> Result<Response<proto::$output>, Status> {
                self.check(&request)?;
                RpcService::$method(&self.real, request).await
            })+
        }
    };
}

delegate_methods! {
    (get_proxy, GetProxyRequest, GetProxyResponse),
    (list_proxies, ListProxiesRequest, ListProxiesResponse),
    (update_proxy_draft, UpdateProxyDraftRequest, UpdateProxyDraftResponse),
    (validate_proxy, ValidateProxyRequest, ValidateProxyResponse),
    (discover_upstream, DiscoverUpstreamRequest, DiscoverUpstreamResponse),
    (test_proxy_connection, TestProxyConnectionRequest, TestProxyConnectionResponse),
    (publish_proxy_revision, PublishProxyRevisionRequest, PublishProxyRevisionResponse),
    (deploy_proxy, DeployProxyRequest, DeployProxyResponse),
    (pause_proxy, PauseProxyRequest, PauseProxyResponse),
    (resume_proxy, ResumeProxyRequest, ResumeProxyResponse),
    (rotate_proxy_credentials, RotateProxyCredentialsRequest, RotateProxyCredentialsResponse),
    (rollback_proxy, RollbackProxyRequest, RollbackProxyResponse),
    (retire_proxy, RetireProxyRequest, RetireProxyResponse),
    (list_proxy_activity, ListProxyActivityRequest, ListProxyActivityResponse),
    (list_proxy_revisions, ListProxyRevisionsRequest, ListProxyRevisionsResponse),
    (get_proxy_operation, GetProxyOperationRequest, GetProxyOperationResponse),
    (list_proxy_bindings, ListProxyBindingsRequest, ListProxyBindingsResponse),
    (list_proxy_approvals, ListProxyApprovalsRequest, ListProxyApprovalsResponse),
    (decide_proxy_approval, DecideProxyApprovalRequest, DecideProxyApprovalResponse),
    (get_proxy_trace, GetProxyTraceRequest, GetProxyTraceResponse),
}
