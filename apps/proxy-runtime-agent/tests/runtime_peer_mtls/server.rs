//! Only a bounded test listener using canonical generated RPCs. No runtime work.

use super::support::*;
use apex_auth::{RuntimePeerError, RuntimePeerPolicy, RuntimePeerRole};
use apex_proxy_runtime_agent::proto::{
    self,
    proxy_runtime_agent_server::{ProxyRuntimeAgent, ProxyRuntimeAgentServer},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{sync::oneshot, task::JoinHandle};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Server as TonicServer, ServerTlsConfig, server::TcpIncoming},
};

#[derive(Clone, Debug)]
pub struct Evidence {
    pub identity: String,
    pub role: RuntimePeerRole,
    pub installation: String,
    pub workspace: String,
    pub namespace: String,
    pub version: String,
    pub checked_at: u64,
}

pub struct State {
    calls: AtomicUsize,
    actions: AtomicUsize,
    evidence: Mutex<Vec<Evidence>>,
}

impl State {
    pub fn counts(&self) -> (usize, usize) {
        (
            self.calls.load(Ordering::SeqCst),
            self.actions.load(Ordering::SeqCst),
        )
    }
    pub fn evidence(&self) -> Vec<Evidence> {
        self.evidence.lock().unwrap().clone()
    }
}

pub struct Server {
    pub endpoint: String,
    pub state: Arc<State>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl Server {
    pub fn start(pki: &Pki, document: &serde_json::Value) -> Self {
        // Standard TLS crypto provider selection; certificate validation and
        // mandatory client authentication remain enabled without any bypass.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let state = Arc::new(State {
            calls: AtomicUsize::new(0),
            actions: AtomicUsize::new(0),
            evidence: Mutex::new(Vec::new()),
        });
        let policy = RuntimePeerPolicy::parse_json(&serde_json::to_vec(document).unwrap());
        // Keep RED parse refusal at the real handler: a refusal stub must not
        // prevent TLS setup and masquerade as a missing fixture/compile failure.
        let service = TestService {
            policy,
            state: Arc::clone(&state),
        };
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(false)
            .timeout(CONNECT);
        let mut server = TonicServer::builder()
            .tls_config(tls)
            .expect("test TLS setup failed")
            .concurrency_limit_per_connection(4)
            .timeout(RPC);
        let incoming =
            TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("owned loopback bind failed");
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let service = ProxyRuntimeAgentServer::new(service)
            .max_decoding_message_size(4096)
            .max_encoding_message_size(4096);
        let (stop, stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
        });
        Self {
            endpoint,
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let outcome = within(self.task.as_mut().expect("owned server task")).await;
        self.task.take();
        outcome
            .expect("owned server task panicked")
            .expect("owned server failed");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct TestService {
    policy: Result<RuntimePeerPolicy, RuntimePeerError>,
    state: Arc<State>,
}

impl TestService {
    fn check<T>(
        &self,
        request: &Request<T>,
        target: &proto::RuntimeTarget,
        role: RuntimePeerRole,
    ) -> Result<(), Status> {
        if self.state.calls.fetch_add(1, Ordering::SeqCst) >= 32 {
            return Err(Status::resource_exhausted("TEST_REQUEST_LIMIT"));
        }
        let installation = request
            .metadata()
            .get("x-test-installation-id")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::invalid_argument("TEST_SELECTOR_REQUIRED"))?;
        let policy = self.policy.as_ref().map_err(|error| status(*error))?;
        // Real public API; never synthesize TlsConnectInfo, accept a body pin,
        // or substitute an operator credential resolver.
        let peer = policy
            .authorize(
                request,
                role,
                installation,
                &target.workspace_id,
                &target.namespace_id,
            )
            .map_err(status)?;
        let mut evidence = self.state.evidence.lock().unwrap();
        if evidence.len() >= 32 {
            return Err(Status::resource_exhausted("TEST_EVIDENCE_LIMIT"));
        }
        evidence.push(Evidence {
            identity: peer.identity_id().into(),
            role: peer.role(),
            installation: peer.installation_id().into(),
            workspace: peer.workspace_id().into(),
            namespace: peer.namespace_id().into(),
            version: peer.policy_version().into(),
            checked_at: peer.checked_at_unix_us(),
        });
        // A test-only post-auth action counter, NOT an engine/ready transition.
        self.state.actions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn status(error: RuntimePeerError) -> Status {
    match error {
        RuntimePeerError::Unauthenticated => Status::unauthenticated(error.code()),
        RuntimePeerError::Denied => Status::permission_denied(error.code()),
        RuntimePeerError::InvalidSelector => Status::invalid_argument(error.code()),
        RuntimePeerError::ClockUnavailable => Status::unavailable(error.code()),
        RuntimePeerError::InvalidPolicy | RuntimePeerError::PolicyNotCurrent => {
            Status::failed_precondition(error.code())
        }
    }
}

#[tonic::async_trait]
impl ProxyRuntimeAgent for TestService {
    async fn inspect_runtime(
        &self,
        request: Request<proto::RuntimeTarget>,
    ) -> Result<Response<proto::RuntimeObservation>, Status> {
        self.check(&request, request.get_ref(), RuntimePeerRole::Controller)?;
        Ok(Response::new(proto::RuntimeObservation {
            state: ACK.into(),
            ..Default::default()
        }))
    }

    async fn probe_upstream(
        &self,
        request: Request<proto::ProbeUpstreamRequest>,
    ) -> Result<Response<proto::UpstreamProbeObservation>, Status> {
        let target = request
            .get_ref()
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("TEST_TARGET_REQUIRED"))?;
        self.check(&request, target, RuntimePeerRole::Agent)?;
        Ok(Response::new(proto::UpstreamProbeObservation {
            error_code: ACK.into(),
            ..Default::default()
        }))
    }

    async fn ensure_runtime(
        &self,
        _: Request<proto::EnsureRuntimeRequest>,
    ) -> Result<Response<proto::RuntimeObservation>, Status> {
        Err(Status::unimplemented("TEST_ONLY_NO_RUNTIME_EFFECTS"))
    }
    async fn set_admission(
        &self,
        _: Request<proto::SetRuntimeAdmissionRequest>,
    ) -> Result<Response<proto::RuntimeObservation>, Status> {
        Err(Status::unimplemented("TEST_ONLY_NO_RUNTIME_EFFECTS"))
    }
    async fn drain_runtime(
        &self,
        _: Request<proto::DrainRuntimeRequest>,
    ) -> Result<Response<proto::RuntimeObservation>, Status> {
        Err(Status::unimplemented("TEST_ONLY_NO_RUNTIME_EFFECTS"))
    }
    async fn remove_runtime(
        &self,
        _: Request<proto::RuntimeTarget>,
    ) -> Result<Response<proto::RuntimeObservation>, Status> {
        Err(Status::unimplemented("TEST_ONLY_NO_RUNTIME_EFFECTS"))
    }
}
