//! Actual loopback mTLS with the production service; not binary-root wiring.
use crate::pki::Pki;
use apex_control_plane_api::{
    RuntimeAuthorityService, bounded_runtime_authority_service_server,
    proto::runtime_authority_service_client::RuntimeAuthorityServiceClient,
};
use std::{future::Future, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Server, ServerTlsConfig, server::TcpIncoming,
};

const BOUND: Duration = Duration::from_secs(8);

pub(super) struct Task<T>(pub JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(BOUND, future)
        .await
        .expect("test watchdog, never accepted refusal")
}

pub async fn client(
    pki: &Pki,
    endpoint: &str,
    leaf: &str,
) -> RuntimeAuthorityServiceClient<Channel> {
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .identity(pki.identity("trusted-host", leaf));
    let channel = within(
        Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(6))
            .connect(),
    )
    .await
    .expect("actual trusted TLS connection");
    RuntimeAuthorityServiceClient::new(channel)
        .max_decoding_message_size(4096)
        .max_encoding_message_size(4096)
}

pub fn exercise<F, Fut, T>(service: RuntimeAuthorityService, pki: &Pki, body: F) -> T
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let tls = ServerTlsConfig::new()
        .identity(pki.identity("trusted-host", "control-plane-server"))
        .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .client_auth_optional(false)
        .timeout(Duration::from_secs(2));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async move {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = incoming.local_addr().unwrap();
        let endpoint = format!("https://{address}");
        let (stop, stopped) = oneshot::channel();
        let router = Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(bounded_runtime_authority_service_server(service));
        let mut server = Task(tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
        }));
        let mut case = Task(tokio::spawn(async move { body(endpoint).await }));
        let outcome = tokio::time::timeout(Duration::from_secs(30), &mut case.0).await;
        if outcome.is_err() {
            case.0.abort();
            let _ = within(&mut case.0).await;
        }
        let _ = stop.send(());
        within(&mut server.0)
            .await
            .expect("owned listener task")
            .expect("graceful listener exit");
        drop(TcpIncoming::bind(address).expect("exact test listener released"));
        outcome
            .expect("case watchdog failure after cleanup")
            .expect("case assertions after cleanup")
    })
}
