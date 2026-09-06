//! Transport envelope limits only; synthetic payloads are not accepted semantics.
use super::*;
struct Envelope;
#[tonic::async_trait]
impl RuntimeExecutionService for Envelope {
    async fn reconcile_runtime(
        &self,
        r: Request<proto::RuntimeReconcileRequest>,
    ) -> Result<Response<proto::RuntimeReconcileResponse>, Status> {
        Ok(Response::new(proto::RuntimeReconcileResponse {
            error_code: "x".repeat(if r.get_ref().schema_version == 2 {
                17_000
            } else {
                8_000
            }),
            ..Default::default()
        }))
    }
}
#[tokio::test]
async fn actual_transport_accepts_8k_response_refuses_over_16k_and_keeps_4k_request_cap() {
    let pki = Pki::require();
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let endpoint = format!("https://{}", incoming.local_addr().unwrap());
    let (shutdown, mut stopped) = watch::channel(false);
    let tls = ServerTlsConfig::new()
        .identity(pki.identity("trusted-host", "control-plane-server"))
        .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .client_auth_optional(false);
    let task = tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(super::super::bounded_service(Envelope))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = stopped.changed().await;
            }),
    );
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .identity(pki.identity("trusted-host", CONTROLLER));
    let mut c = RuntimeExecutionServiceClient::new(
        Endpoint::from_shared(endpoint)
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    )
    .max_decoding_message_size(16_384)
    .max_encoding_message_size(8192);
    assert_eq!(
        c.reconcile_runtime(request())
            .await
            .unwrap()
            .into_inner()
            .error_code
            .len(),
        8_000
    );
    let mut r = request();
    r.schema_version = 2;
    assert!(c.reconcile_runtime(r).await.is_err());
    let mut r = request();
    r.command_id = "x".repeat(4500);
    assert!(c.reconcile_runtime(r).await.is_err());
    drop(c);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}
