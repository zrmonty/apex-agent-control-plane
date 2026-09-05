//! Test-only generated callback: pair evidence stays local; no PG snapshot ever.

use super::{pki::Pki, support::*};
use apex_auth::{RuntimePeerError, RuntimePeerPolicy};
use apex_proxy_runtime_agent::proto::{
    CheckRuntimeAuthorityRequest, RuntimeAuthoritySnapshot,
    runtime_authority_service_server::{RuntimeAuthorityService, RuntimeAuthorityServiceServer},
};
use serde_json::Value;
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
    pub agent: String,
    pub observed_controller: String,
    pub installation: String,
    pub workspace: String,
    pub namespace: String,
    pub version: String,
    pub checked: u64,
    pub debug: String,
}

#[derive(Default)]
pub struct State {
    calls: AtomicUsize,
    evidence: Mutex<Vec<Evidence>>,
}

impl State {
    pub fn counts(&self) -> (usize, usize) {
        (
            self.calls.load(Ordering::SeqCst),
            self.evidence.lock().unwrap().len(),
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
    pub fn start(pki: &Pki, document: &Value) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let policy = RuntimePeerPolicy::parse_json(&serde_json::to_vec(document).unwrap())
            .expect("pair fixture policy must be structurally valid before TLS starts");
        let state = Arc::new(State::default());
        let service = PairService {
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
            .unwrap()
            .concurrency_limit_per_connection(4)
            .timeout(RPC);
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let service = RuntimeAuthorityServiceServer::new(service)
            .max_decoding_message_size(4096)
            .max_encoding_message_size(4096);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
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
        // Keep the handle in the guard during the watchdog; timeout/unwind
        // aborts this exact owned task, rather than detaching its listener.
        let outcome = within(self.task.as_mut().expect("owned pair listener")).await;
        self.task.take();
        outcome
            .expect("pair listener task panicked")
            .expect("pair listener failed");
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

struct PairService {
    policy: RuntimePeerPolicy,
    state: Arc<State>,
}

#[tonic::async_trait]
impl RuntimeAuthorityService for PairService {
    async fn check_runtime_authority(
        &self,
        request: Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<RuntimeAuthoritySnapshot>, Status> {
        let body = request.get_ref();
        let target = body
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("TEST_TARGET_REQUIRED"))?;
        let observed: &[u8; 32] = body
            .observed_controller_certificate_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("TEST_PIN_REQUIRED"))?;
        if self.state.calls.fetch_add(1, Ordering::SeqCst) >= 64 {
            return Err(Status::resource_exhausted("TEST_PAIR_CALL_LIMIT"));
        }
        // The only tested production boundary. No constructed TLS extension,
        // public pin override for the Agent, alternate role, or test success.
        let pair = self
            .policy
            .authorize_agent_observation(
                &request,
                observed,
                &body.installation_id,
                &target.workspace_id,
                &target.namespace_id,
            )
            .map_err(status)?;
        let mut evidence = self.state.evidence.lock().unwrap();
        if evidence.len() >= 64 {
            return Err(Status::resource_exhausted("TEST_PAIR_EVIDENCE_LIMIT"));
        }
        evidence.push(Evidence {
            agent: pair.agent_identity_id().into(),
            observed_controller: pair.observed_controller_identity_id().into(),
            installation: pair.installation_id().into(),
            workspace: pair.workspace_id().into(),
            namespace: pair.namespace_id().into(),
            version: pair.policy_version().into(),
            checked: pair.checked_at_unix_us(),
            debug: format!("{pair:?}"),
        });
        // A marked test-only stop AFTER the check, never a successful authority
        // response. In particular do not serialize the local clock as DB time.
        Err(Status::unimplemented(CHECKED))
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
