//! Synthetic valid snapshot over real pinned mTLS; no production authority grant.
use super::*;
use crate::{
    authority::AuthorityClientConfig,
    proto::runtime_authority_service_server::{
        RuntimeAuthorityService, RuntimeAuthorityServiceServer,
    },
};
use tonic::{
    Response,
    transport::{
        Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig, server::TcpIncoming,
    },
};
#[path = "../../../../../tests/runtime_peer_pair/pki.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Reuse the unchanged private TLS fixture without widening unrelated test modules"
)]
mod pki;
pub(super) const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub(super) async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("held RPC watchdog")
}
struct Listener(tokio::task::JoinHandle<Result<(), tonic::transport::Error>>);
impl Listener {
    fn start(pki: &pki::Pki, service: impl RuntimeAuthorityService) -> (Self, String) {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let tls = ServerTlsConfig::new()
            .identity(pki.identity("trusted-host", "control-plane-server"))
            .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")));
        let mut server = Server::builder().tls_config(tls).unwrap();
        (
            Self(tokio::spawn(async move {
                server
                    .add_service(RuntimeAuthorityServiceServer::new(service))
                    .serve_with_incoming(incoming)
                    .await
            })),
            endpoint,
        )
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Capture(Mutex<Option<oneshot::Sender<Request<proto::RuntimeReconcileRequest>>>>);
#[tonic::async_trait]
impl RuntimeAuthorityService for Capture {
    async fn check_runtime_authority(
        &self,
        request: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeAuthoritySnapshot>, Status> {
        let (metadata, extensions, body) = request.into_parts();
        let request = Request::from_parts(
            metadata,
            extensions,
            proto::RuntimeReconcileRequest {
                schema_version: 1,
                target: body.target,
                operation_id: body.operation_id,
                command_id: body.command_id,
                config_hash: "a".repeat(64),
            },
        );
        self.0
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(request)
            .unwrap();
        Err(Status::unimplemented("TEST_CAPTURED_ACTUAL_TLS_REQUEST"))
    }
}
struct Callback {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    metadata: Arc<owner::Metadata>,
    lease_us: u64,
}
#[tonic::async_trait]
impl RuntimeAuthorityService for Callback {
    async fn check_runtime_authority(
        &self,
        request: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeAuthoritySnapshot>, Status> {
        let b = request.get_ref();
        let target = b.target.as_ref().unwrap();
        let pin = b
            .observed_controller_certificate_sha256
            .as_slice()
            .try_into()
            .unwrap();
        self.metadata
            .policy
            .authorize_agent_observation(
                &request,
                pin,
                INSTALL,
                &target.workspace_id,
                &target.namespace_id,
            )
            .unwrap();
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Ok(Response::new(proto::RuntimeAuthoritySnapshot {
            schema_version: 1,
            target: Some(target.clone()),
            operation_id: b.operation_id.clone(),
            command_id: b.command_id.clone(),
            action: 1,
            installation_id: INSTALL.into(),
            agent_identity_id: "agent".into(),
            observed_controller_identity_id: "controller".into(),
            peer_policy_version: "client-policy".into(),
            enrollment_version: "enrollment-1".into(),
            host_policy_version: "host-1".into(),
            desired_state: 1,
            observed_state: 1,
            config_hash: "a".repeat(64),
            checked_at_unix_us: 9_007_199_254_740_993,
            lease_expires_at_unix_us: 9_007_199_254_740_993 + self.lease_us,
        }))
    }
}
pub(super) struct Fixture {
    pki: pki::Pki,
    listener: Listener,
    pub client: Arc<RuntimeAuthorityClient>,
    pub metadata: Arc<owner::Metadata>,
    pub entered: Arc<Semaphore>,
    pub release: Arc<Semaphore>,
}
impl Fixture {
    pub async fn start_with_lease(lease_us: u64) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = pki::Pki::require();
        let (policy, catalog) = owner::tests::documents();
        let mut policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        policy["peers"][0]["certificateSha256"] = pki::hex(&pki.pin(pki::CONTROLLER)).into();
        let mut agent = policy["peers"][0].clone();
        agent["certificateSha256"] = pki::hex(&pki.pin(pki::AGENT)).into();
        agent["identityId"] = "agent".into();
        agent["role"] = "agent".into();
        policy["peers"].as_array_mut().unwrap().push(agent);
        let metadata = Arc::new(
            owner::Metadata::parse(&serde_json::to_vec(&policy).unwrap(), &catalog).unwrap(),
        );
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (listener, endpoint) = Listener::start(
            &pki,
            Callback {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                metadata: Arc::clone(&metadata),
                lease_us,
            },
        );
        let client = Arc::new(
            within(RuntimeAuthorityClient::connect(AuthorityClientConfig {
                endpoint,
                tls_server_name: "control-plane-api".into(),
                ca_pem: pki.read("trusted-host", "ca.pem"),
                client_certificate_pem: pki.read("trusted-host", &format!("{}.pem", pki::AGENT)),
                client_key_pem: pki.read("trusted-host", &format!("{}.key", pki::AGENT)),
                installation_id: INSTALL.into(),
                agent_identity_id: "agent".into(),
                enrollment_version: "enrollment-1".into(),
                host_policy_version: "host-1".into(),
            }))
            .await
            .unwrap(),
        );
        Self {
            pki,
            listener,
            client,
            metadata,
            entered,
            release,
        }
    }
    pub async fn request(&self) -> Request<proto::RuntimeReconcileRequest> {
        let (sent, received) = oneshot::channel();
        let (listener, endpoint) = Listener::start(&self.pki, Capture(Mutex::new(Some(sent))));
        let tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(
                self.pki.read("trusted-host", "ca.pem"),
            ))
            .identity(self.pki.identity("trusted-host", pki::CONTROLLER));
        let channel = within(
            Endpoint::from_shared(endpoint)
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect(),
        )
        .await
        .unwrap();
        let mut client =
            proto::runtime_authority_service_client::RuntimeAuthorityServiceClient::new(channel);
        let target = proto::RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
            revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            generation: 1,
            fencing_token: 1,
        };
        let result = within(
            client.check_runtime_authority(proto::CheckRuntimeAuthorityRequest {
                schema_version: 1,
                target: Some(target),
                operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
                command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            result.unwrap_err().message(),
            "TEST_CAPTURED_ACTUAL_TLS_REQUEST"
        );
        drop(listener);
        within(received).await.unwrap()
    }
    pub async fn close(mut self) -> Result<(), tokio::time::error::Elapsed> {
        self.listener.0.abort();
        tokio::time::timeout(Duration::from_secs(10), &mut self.listener.0)
            .await
            .map(|_| ())
    }
}
