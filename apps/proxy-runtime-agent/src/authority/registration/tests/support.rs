//! Test-only real TLS fixture; synthetic receipt is not PG/staging acceptance.
use super::*;
use apex_auth::RuntimePeerPolicy;
use serde_json::json;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

#[path = "../../../../tests/runtime_peer_pair/pki.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Reuse the unchanged private TLS fixture without widening unrelated test modules"
)]
pub mod pki;
pub use pki::{AGENT, CONTROLLER, OTHER, Pki};
pub const BUDGET: Duration = Duration::from_secs(2);
pub const CANARY: &str = "registration-private-canary";

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("TLS fixture watchdog")
}

pub fn client_config(pki: &Pki, endpoint: &str) -> AuthorityClientConfig {
    let mut value = config();
    value.endpoint = endpoint.into();
    value.tls_server_name = "control-plane-api".into();
    value.ca_pem = pki.read("trusted-host", "ca.pem");
    value.client_certificate_pem = pki.read("trusted-host", &format!("{AGENT}.pem"));
    value.client_key_pem = pki.read("trusted-host", &format!("{AGENT}.key"));
    value
}

pub fn policy(pki: &Pki, lifetime: Duration, revoked: bool) -> Arc<RuntimePeerPolicy> {
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let grant = json!({"installationId":INSTALL,"workspaceId":"work","namespaceId":"ns"});
    let document = json!({"schemaVersion":1,"version":"client-policy",
    "validFromUnixUs":(now-60_000_000).to_string(),"expiresAtUnixUs":(now+u64::try_from(lifetime.as_micros()).unwrap()).to_string(),
    "peers":[
        {"certificateSha256":pki::hex(&pki.pin(AGENT)),"identityId":"client-agent","role":"agent","revoked":false,"grants":[grant]},
        {"certificateSha256":pki::hex(&pki.pin(CONTROLLER)),"identityId":"client-controller","role":"controller","revoked":revoked,"grants":[grant]}
    ]});
    Arc::new(RuntimePeerPolicy::parse_json(&serde_json::to_vec(&document).unwrap()).unwrap())
}

pub fn query() -> Request<proto::RegisterRuntimeDeploymentRequest> {
    let mut request = Request::new(proto::RegisterRuntimeDeploymentRequest {
        authority: Some(proto::CheckRuntimeAuthorityRequest {
            schema_version: 1,
            target: Some(target()),
            operation_id: OPERATION.into(),
            command_id: COMMAND.into(),
            action: 1,
            installation_id: "caller-cannot-route-this".into(),
            observed_controller_certificate_sha256: vec![0xff; 32],
        }),
        attestation: Some(attestation()),
    });
    for name in [
        "authorization",
        "x-runtime-role",
        "x-peer-certificate-sha256",
        "x-forwarded-client-cert",
    ] {
        request.metadata_mut().insert(name, CANARY.parse().unwrap());
    }
    request
}

pub async fn caller(
    pki: &Pki,
    endpoint: &str,
    leaf: Option<&str>,
) -> proto::runtime_deployment_registry_client::RuntimeDeploymentRegistryClient<Channel> {
    let mut tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")));
    if let Some(leaf) = leaf {
        tls = tls.identity(pki.identity("trusted-host", leaf));
    }
    let channel = within(
        Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_timeout(BUDGET)
            .connect(),
    )
    .await
    .unwrap();
    proto::runtime_deployment_registry_client::RuntimeDeploymentRegistryClient::new(channel)
        .max_encoding_message_size(65_536)
        .max_decoding_message_size(REPLY_LIMIT)
}
