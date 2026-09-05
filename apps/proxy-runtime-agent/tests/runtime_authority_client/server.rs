use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use apex_auth::RuntimePeerPolicy;
use apex_proxy_runtime_agent::{
    authority::{AuthorityOperation, RuntimeAuthorityClient},
    proto::{
        CheckRuntimeAuthorityRequest, RuntimeAuthoritySnapshot,
        runtime_authority_service_server::{
            RuntimeAuthorityService, RuntimeAuthorityServiceServer,
        },
    },
};
use tokio::{
    sync::{Notify, Semaphore, oneshot},
    task::JoinHandle,
};
use tonic::{
    Code, Request, Response, Status,
    transport::{Certificate, Server as TonicServer, ServerTlsConfig, server::TcpIncoming},
};

use super::{pki::Pki, support::*};

pub struct Listener {
    pub endpoint: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl Listener {
    pub fn start(pki: &Pki, service: impl RuntimeAuthorityService, optional_client: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(optional_client)
            .timeout(BUDGET);
        let mut server = TonicServer::builder()
            .tls_config(tls)
            .unwrap()
            .concurrency_limit_per_connection(16)
            .timeout(Duration::from_secs(8));
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(
                    RuntimeAuthorityServiceServer::new(service)
                        .max_decoding_message_size(4096)
                        // Oversized response case must reach the production client's decoder.
                        .max_encoding_message_size(8192),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            endpoint,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let result = within(self.task.as_mut().unwrap()).await;
        self.task.take();
        result.expect("listener task").expect("listener service");
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub struct CallbackState {
    pub snapshot: Mutex<RuntimeAuthoritySnapshot>,
    pub refusal: Mutex<Option<Code>>,
    pub calls: AtomicUsize,
    pub active: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Semaphore,
    pub release: Semaphore,
    pub departed: Semaphore,
    pub request: Mutex<Option<CheckRuntimeAuthorityRequest>>,
    pub leaked_metadata: AtomicBool,
}

impl CallbackState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: Mutex::new(snapshot()),
            refusal: Mutex::new(None),
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            departed: Semaphore::new(0),
            request: Mutex::new(None),
            leaked_metadata: AtomicBool::new(false),
        })
    }

    pub async fn wait_entered(&self, count: u32) {
        within(self.entered.acquire_many(count))
            .await
            .unwrap()
            .forget();
    }

    pub async fn wait_departed(&self, count: u32) {
        within(self.departed.acquire_many(count))
            .await
            .unwrap()
            .forget();
    }
}

struct Active(Arc<CallbackState>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.departed.add_permits(1);
    }
}

pub struct Callback {
    pub state: Arc<CallbackState>,
    pub policy: Arc<RuntimePeerPolicy>,
}

#[tonic::async_trait]
impl RuntimeAuthorityService for Callback {
    async fn check_runtime_authority(
        &self,
        request: Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<RuntimeAuthoritySnapshot>, Status> {
        let state = &self.state;
        if state.calls.fetch_add(1, Ordering::SeqCst) >= 128 {
            return Err(Status::resource_exhausted("test callback call bound"));
        }
        let body = request.get_ref();
        let target = body
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("test target"))?;
        let pin = body
            .observed_controller_certificate_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("test leaf"))?;
        let pair = self
            .policy
            .authorize_agent_observation(
                &request,
                pin,
                &body.installation_id,
                &target.workspace_id,
                &target.namespace_id,
            )
            .map_err(|_| Status::permission_denied("test pair"))?;
        assert_eq!(pair.agent_identity_id(), "client-agent");
        assert_eq!(pair.observed_controller_identity_id(), "client-controller");
        assert_eq!(body.schema_version, 1);
        assert_eq!(body.action, 1);
        assert_eq!(body.installation_id, INSTALL);
        for name in [
            "authorization",
            "x-runtime-role",
            "x-runtime-identity",
            "x-peer-certificate-sha256",
            "x-forwarded-client-cert",
        ] {
            if request.metadata().get(name).is_some() {
                state.leaked_metadata.store(true, Ordering::SeqCst);
            }
        }
        assert!(
            request.metadata().get("grpc-timeout").is_some(),
            "remaining timeout must be sent"
        );
        *state.request.lock().unwrap() = Some(body.clone());
        state.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(Arc::clone(state));
        state.entered.add_permits(1);
        if state.hold.load(Ordering::SeqCst) {
            state.release.acquire().await.unwrap().forget();
        }
        if let Some(code) = *state.refusal.lock().unwrap() {
            return Err(Status::new(code, CANARY));
        }
        Ok(Response::new(state.snapshot.lock().unwrap().clone()))
    }
}

pub struct Settings {
    pub policy: Arc<RuntimePeerPolicy>,
    pub budget: Duration,
    pub config_hash: String,
}

pub struct IngressState {
    pub settings: Mutex<Settings>,
    pub cancel: Notify,
}

pub struct Ingress {
    pub client: Arc<RuntimeAuthorityClient>,
    pub state: Arc<IngressState>,
}

#[tonic::async_trait]
impl RuntimeAuthorityService for Ingress {
    async fn check_runtime_authority(
        &self,
        request: Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<RuntimeAuthoritySnapshot>, Status> {
        let (policy, budget, config_hash) = {
            let settings = self.state.settings.lock().unwrap();
            (
                Arc::clone(&settings.policy),
                settings.budget,
                settings.config_hash.clone(),
            )
        };
        let body = request.get_ref();
        let operation = AuthorityOperation {
            target: body
                .target
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("test target"))?,
            operation_id: &body.operation_id,
            command_id: &body.command_id,
            config_hash: &config_hash,
        };
        // This real handler owns and drops the production future on cancellation.
        tokio::select! {
            result = self.client.check(&request, &policy, operation, budget) => result.map(Response::new).map_err(status),
            () = self.state.cancel.notified() => Err(Status::cancelled("test owner cancelled")),
        }
    }
}

pub struct Fixture {
    pub callback: Listener,
    pub ingress: Listener,
    pub state: Arc<CallbackState>,
    pub incoming: Arc<IngressState>,
    pub client: Arc<RuntimeAuthorityClient>,
}

impl Fixture {
    pub async fn start(pki: &Pki) -> Self {
        let policy = policy(pki, "client-policy", false);
        let state = CallbackState::new();
        let callback = Listener::start(
            pki,
            Callback {
                state: Arc::clone(&state),
                policy: Arc::clone(&policy),
            },
            false,
        );
        let client = Arc::new(
            within(RuntimeAuthorityClient::connect(config(
                pki,
                &callback.endpoint,
            )))
            .await
            .expect("production connect must establish pinned mTLS"),
        );
        let incoming = Arc::new(IngressState {
            settings: Mutex::new(Settings {
                policy,
                budget: BUDGET,
                config_hash: HASH.into(),
            }),
            cancel: Notify::new(),
        });
        let ingress = Listener::start(
            pki,
            Ingress {
                client: Arc::clone(&client),
                state: Arc::clone(&incoming),
            },
            true,
        );
        Self {
            callback,
            ingress,
            state,
            incoming,
            client,
        }
    }

    pub async fn shutdown(self) {
        self.incoming.cancel.notify_waiters();
        self.state.release.add_permits(16);
        self.ingress.shutdown().await;
        self.callback.shutdown().await;
    }
}
