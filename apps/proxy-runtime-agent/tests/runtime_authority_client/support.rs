use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apex_auth::RuntimePeerPolicy;
use apex_proxy_runtime_agent::{
    authority::{AuthorityClientConfig, AuthorityClientError},
    proto,
};
use serde_json::json;
use tonic::{
    Code, Request,
    transport::{Certificate, ClientTlsConfig, Endpoint},
};

use super::pki::{AGENT, CONTROLLER, Pki, hex};

pub const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const BUDGET: Duration = Duration::from_secs(2);
pub const CANARY: &str = "authority-private-canary";

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("client fixture watchdog")
}

pub fn config(pki: &Pki, endpoint: &str) -> AuthorityClientConfig {
    AuthorityClientConfig {
        endpoint: endpoint.into(),
        tls_server_name: "control-plane-api".into(),
        ca_pem: pki.read("trusted-host", "ca.pem"),
        client_certificate_pem: pki.read("trusted-host", &format!("{AGENT}.pem")),
        client_key_pem: pki.read("trusted-host", &format!("{AGENT}.key")),
        installation_id: INSTALL.into(),
        agent_identity_id: "client-agent".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
    }
}

pub fn policy(pki: &Pki, version: &str, revoked: bool) -> Arc<RuntimePeerPolicy> {
    policy_for(pki, version, revoked, Duration::from_secs(60))
}

pub fn policy_for(
    pki: &Pki,
    version: &str,
    revoked: bool,
    lifetime: Duration,
) -> Arc<RuntimePeerPolicy> {
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let grant = json!({"installationId": INSTALL, "workspaceId": "work", "namespaceId": "ns"});
    let value = json!({
        "schemaVersion": 1, "version": version,
        "validFromUnixUs": (now - 60_000_000).to_string(),
        "expiresAtUnixUs": (now + u64::try_from(lifetime.as_micros()).unwrap()).to_string(),
        "peers": [
            {"certificateSha256": hex(&pki.pin(AGENT)), "identityId": "client-agent",
             "role": "agent", "revoked": false, "grants": [grant.clone()]},
            {"certificateSha256": hex(&pki.pin(CONTROLLER)), "identityId": "client-controller",
             "role": "controller", "revoked": revoked, "grants": [grant]}
        ]
    });
    Arc::new(RuntimePeerPolicy::parse_json(&serde_json::to_vec(&value).unwrap()).unwrap())
}

pub fn target() -> proto::RuntimeTarget {
    proto::RuntimeTarget {
        workspace_id: "work".into(),
        namespace_id: "ns".into(),
        proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
        revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
        generation: 9_007_199_254_740_993,
        fencing_token: 9_007_199_254_740_995,
    }
}

pub fn query() -> Request<proto::CheckRuntimeAuthorityRequest> {
    let mut request = Request::new(proto::CheckRuntimeAuthorityRequest {
        schema_version: 1,
        target: Some(target()),
        operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
        command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
        action: 1,
        // Test ingress deliberately sends bogus attestation: production must derive its own.
        installation_id: "caller-cannot-route-this".into(),
        observed_controller_certificate_sha256: vec![0xff; 32],
    });
    for name in [
        "authorization",
        "x-runtime-role",
        "x-runtime-identity",
        "x-peer-certificate-sha256",
        "x-forwarded-client-cert",
    ] {
        request.metadata_mut().insert(name, CANARY.parse().unwrap());
    }
    request
}

pub fn snapshot() -> proto::RuntimeAuthoritySnapshot {
    // Hand-authored callback answer, never copied from the caller's request.
    // DB timestamps are SYNTHETIC; main owns proof against actual PG/control-root.
    proto::RuntimeAuthoritySnapshot {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
            revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            generation: 9_007_199_254_740_993,
            fencing_token: 9_007_199_254_740_995,
        }),
        operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
        command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
        action: 1,
        installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
        agent_identity_id: "client-agent".into(),
        observed_controller_identity_id: "client-controller".into(),
        peer_policy_version: "client-policy".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
        desired_state: 1,
        observed_state: 1,
        config_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        checked_at_unix_us: 9_007_199_254_740_993,
        lease_expires_at_unix_us: 9_007_199_264_740_993,
    }
}

pub async fn ingress_client(
    pki: &Pki,
    endpoint: &str,
    leaf: Option<&str>,
) -> proto::runtime_authority_service_client::RuntimeAuthorityServiceClient<tonic::transport::Channel>
{
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
            .buffer_size(8)
            .connect_timeout(BUDGET)
            .connect(),
    )
    .await
    .unwrap();
    proto::runtime_authority_service_client::RuntimeAuthorityServiceClient::new(channel)
        .max_encoding_message_size(4096)
        .max_decoding_message_size(4096)
}

pub fn status(error: AuthorityClientError) -> tonic::Status {
    let code = match error {
        AuthorityClientError::InvalidConfiguration | AuthorityClientError::InvalidInput => {
            Code::InvalidArgument
        }
        AuthorityClientError::Unauthenticated => Code::Unauthenticated,
        AuthorityClientError::Denied => Code::PermissionDenied,
        AuthorityClientError::Transport | AuthorityClientError::Unavailable => Code::Unavailable,
        AuthorityClientError::Overloaded => Code::ResourceExhausted,
        AuthorityClientError::Deadline => Code::DeadlineExceeded,
        AuthorityClientError::RemoteRefusal => Code::FailedPrecondition,
        AuthorityClientError::InvalidSnapshot | AuthorityClientError::MismatchedSnapshot => {
            Code::DataLoss
        }
    };
    tonic::Status::new(code, error.code())
}

pub fn assert_error(status: tonic::Status, expected: AuthorityClientError) {
    assert_eq!(status.message(), expected.code());
    assert_eq!(status.code(), self::status(expected).code());
    assert!(!format!("{status:?}").contains(CANARY));
}
