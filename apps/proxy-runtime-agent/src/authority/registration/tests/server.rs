use super::{support::*, *};
use apex_auth::RuntimePeerPolicy;
use proto::runtime_deployment_registry_server::{
    RuntimeDeploymentRegistry, RuntimeDeploymentRegistryServer,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{
    sync::{Notify, Semaphore, oneshot},
    task::JoinHandle,
};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Server, ServerTlsConfig, server::TcpIncoming},
};

pub struct Listener {
    pub endpoint: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}
impl Listener {
    fn start(pki: &Pki, service: impl RuntimeDeploymentRegistry, optional: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
            .client_auth_optional(optional)
            .timeout(BUDGET);
        let mut server = Server::builder()
            .tls_config(tls)
            .unwrap()
            .concurrency_limit_per_connection(16);
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(
                    RuntimeDeploymentRegistryServer::new(service)
                        .max_decoding_message_size(65_536)
                        .max_encoding_message_size(65_536),
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
    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        within(self.task.as_mut().unwrap()).await.unwrap().unwrap();
        self.task.take();
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

pub struct State {
    pub reply: Mutex<proto::RuntimeDeploymentRegistrationReceipt>,
    pub sent: Mutex<Option<proto::RegisterRuntimeDeploymentRequest>>,
    pub calls: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Semaphore,
    pub release: Semaphore,
    pub refusal: Mutex<Option<tonic::Code>>,
}
pub struct Settings {
    pub policy: Arc<RuntimePeerPolicy>,
    pub budget: Duration,
}
#[derive(Clone)]
struct Callback {
    state: Arc<State>,
    policy: Arc<RuntimePeerPolicy>,
}
#[tonic::async_trait]
impl RuntimeDeploymentRegistry for Callback {
    async fn register_deployment(
        &self,
        request: Request<proto::RegisterRuntimeDeploymentRequest>,
    ) -> Result<Response<proto::RuntimeDeploymentRegistrationReceipt>, Status> {
        let authority = request.get_ref().authority.as_ref().unwrap();
        let pin = authority
            .observed_controller_certificate_sha256
            .as_slice()
            .try_into()
            .unwrap();
        let pair = self
            .policy
            .authorize_agent_observation(&request, pin, &authority.installation_id, "work", "ns")
            .unwrap();
        assert_eq!(pair.agent_identity_id(), "client-agent");
        assert_eq!(pair.observed_controller_identity_id(), "client-controller");
        assert_eq!(authority.schema_version, 1);
        assert_eq!(authority.action, 1);
        for name in [
            "authorization",
            "x-runtime-role",
            "x-peer-certificate-sha256",
            "x-forwarded-client-cert",
        ] {
            assert!(
                request.metadata().get(name).is_none(),
                "no forwarded spoofed metadata"
            );
        }
        assert!(request.metadata().get("grpc-timeout").is_some());
        *self.state.sent.lock().unwrap() = Some(request.into_inner());
        self.state.calls.fetch_add(1, Ordering::SeqCst);
        self.state.entered.add_permits(1);
        if self.state.hold.load(Ordering::SeqCst) {
            self.state.release.acquire().await.unwrap().forget();
        }
        if let Some(code) = *self.state.refusal.lock().unwrap() {
            return Err(Status::new(code, CANARY));
        }
        Ok(Response::new(self.state.reply.lock().unwrap().clone()))
    }
}
#[derive(Clone)]
struct Ingress {
    client: Arc<RuntimeAuthorityClient>,
    settings: Arc<Mutex<Settings>>,
    cancel: Arc<Notify>,
}
#[tonic::async_trait]
impl RuntimeDeploymentRegistry for Ingress {
    async fn register_deployment(
        &self,
        request: Request<proto::RegisterRuntimeDeploymentRequest>,
    ) -> Result<Response<proto::RuntimeDeploymentRegistrationReceipt>, Status> {
        let (policy, budget) = {
            let settings = self.settings.lock().unwrap();
            (Arc::clone(&settings.policy), settings.budget)
        };
        let body = request.get_ref();
        let authority = body.authority.as_ref().unwrap();
        let operation = AuthorityOperation {
            target: authority.target.as_ref().unwrap(),
            operation_id: &authority.operation_id,
            command_id: &authority.command_id,
            config_hash: HASH,
        };
        tokio::select! {
            result=self.client.register(&request,&policy,operation,body.attestation.as_ref().unwrap(),budget) => {
                result.map(Response::new).map_err(|error| Status::failed_precondition(error.code()))
            }
            ()=self.cancel.notified() => Err(Status::cancelled("fixture owner cancelled")),
        }
    }
}

pub struct Fixture {
    pub callback: Listener,
    pub ingress: Listener,
    pub state: Arc<State>,
    pub client: Arc<RuntimeAuthorityClient>,
    pub settings: Arc<Mutex<Settings>>,
    pub cancel: Arc<Notify>,
}
impl Fixture {
    pub async fn start(pki: &Pki) -> Self {
        let policy = policy(pki, Duration::from_secs(60), false);
        let state = Arc::new(State {
            reply: Mutex::new(receipt()),
            sent: Mutex::new(None),
            calls: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            refusal: Mutex::new(None),
        });
        let callback = Listener::start(
            pki,
            Callback {
                state: Arc::clone(&state),
                policy: Arc::clone(&policy),
            },
            false,
        );
        let client = Arc::new(
            within(RuntimeAuthorityClient::connect(client_config(
                pki,
                &callback.endpoint,
            )))
            .await
            .unwrap(),
        );
        let settings = Arc::new(Mutex::new(Settings {
            policy,
            budget: BUDGET,
        }));
        let cancel = Arc::new(Notify::new());
        let ingress = Listener::start(
            pki,
            Ingress {
                client: Arc::clone(&client),
                settings: Arc::clone(&settings),
                cancel: Arc::clone(&cancel),
            },
            true,
        );
        Self {
            callback,
            ingress,
            state,
            client,
            settings,
            cancel,
        }
    }
    pub async fn shutdown(self) {
        self.cancel.notify_waiters();
        self.state.release.add_permits(16);
        self.ingress.shutdown().await;
        self.callback.shutdown().await;
    }
}
