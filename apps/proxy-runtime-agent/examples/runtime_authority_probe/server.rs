//! Test-only Controller->Agent ingress around the actual production client.
use super::pki::Pki;
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
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Server, ServerTlsConfig, server::TcpIncoming},
};

struct Ingress {
    client: RuntimeAuthorityClient,
    policy: RuntimePeerPolicy,
    config_hash: String,
}

#[tonic::async_trait]
impl RuntimeAuthorityService for Ingress {
    async fn check_runtime_authority(
        &self,
        request: Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<RuntimeAuthoritySnapshot>, Status> {
        let body = request.get_ref();
        let operation = AuthorityOperation {
            target: body
                .target
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("TEST_TARGET"))?,
            operation_id: &body.operation_id,
            command_id: &body.command_id,
            config_hash: &self.config_hash,
        };
        self.client
            .check(&request, &self.policy, operation, Duration::from_secs(4))
            .await
            .map(Response::new)
            .map_err(|error| Status::failed_precondition(error.code()))
    }
}

pub(super) struct Guard {
    pub endpoint: String,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

pub(super) fn start(
    client: RuntimeAuthorityClient,
    policy: RuntimePeerPolicy,
    config_hash: String,
    pki: &Pki,
) -> Result<Guard, ()> {
    let tls = ServerTlsConfig::new()
        .identity(pki.identity("trusted-host", "control-plane-server"))
        .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .client_auth_optional(false)
        .timeout(Duration::from_secs(2));
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().map_err(|_| ())?).map_err(|_| ())?;
    let endpoint = format!("https://{}", incoming.local_addr().map_err(|_| ())?);
    let router = Server::builder()
        .tls_config(tls)
        .map_err(|_| ())?
        .concurrency_limit_per_connection(1)
        .timeout(Duration::from_secs(5))
        .add_service(
            RuntimeAuthorityServiceServer::new(Ingress {
                client,
                policy,
                config_hash,
            })
            .max_decoding_message_size(4096)
            .max_encoding_message_size(4096),
        );
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        router
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
    });
    Ok(Guard {
        endpoint,
        stop: Some(stop),
        task,
    })
}

impl Guard {
    pub async fn finish(mut self) -> Result<(), ()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.abort();
    }
}
