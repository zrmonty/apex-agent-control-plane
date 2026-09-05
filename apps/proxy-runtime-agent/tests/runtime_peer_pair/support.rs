use super::pki::{AGENT, CONTROLLER, Pki, hex};
use apex_proxy_runtime_agent::proto::{
    CheckRuntimeAuthorityRequest, RuntimeAuthorityAction, RuntimeTarget,
    runtime_authority_service_client::RuntimeAuthorityServiceClient,
};
use serde_json::{Value, json};
use std::{
    future::Future,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tonic::{
    Code, Request,
    transport::{Certificate, ClientTlsConfig, Endpoint},
};

pub const INSTALL_A: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub const INSTALL_B: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
pub const CONNECT: Duration = Duration::from_secs(2);
pub const RPC: Duration = Duration::from_secs(2);
pub const CHECKED: &str = "TEST_PAIR_CHECKED_NO_PG_AUTHORITY";

pub fn now_us() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

pub fn grant(installation: &str, workspace: &str, namespace: &str) -> Value {
    json!({"installationId": installation, "workspaceId": workspace, "namespaceId": namespace})
}

pub fn document(pki: &Pki) -> Value {
    let now = now_us();
    json!({
        "schemaVersion": 1, "version": "pair-tls-policy",
        "validFromUnixUs": now.checked_sub(60_000_000).unwrap().to_string(),
        "expiresAtUnixUs": now.checked_add(60_000_000).unwrap().to_string(),
        "peers": [
            {"certificateSha256": hex(&pki.pin(AGENT)), "identityId": "pair-agent",
             "role": "agent", "revoked": false, "grants": [grant(INSTALL_A, "work", "ns")]},
            {"certificateSha256": hex(&pki.pin(CONTROLLER)), "identityId": "pair-controller",
             "role": "controller", "revoked": false, "grants": [grant(INSTALL_A, "work", "ns")]}
        ]
    })
}

pub struct Query<'a> {
    pub installation: &'a str,
    pub workspace: &'a str,
    pub namespace: &'a str,
    pub observed: [u8; 32],
    pub spoof: bool,
}

impl Query<'_> {
    pub fn valid(pki: &Pki) -> Self {
        Self {
            installation: INSTALL_A,
            workspace: "work",
            namespace: "ns",
            observed: pki.pin(CONTROLLER),
            spoof: false,
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Transport,
    LocalTransportStatus(Code),
    Rpc(Code, String),
}

impl Failure {
    fn rpc(status: tonic::Status) -> Self {
        let code = status.code();
        // tonic 0.14 retains a local source for from_error's Unknown and
        // connection-error Unavailable. Wire application statuses have none.
        // Never retain/format the transport message or its source chain.
        if matches!(code, Code::Unknown | Code::Unavailable)
            && std::error::Error::source(&status).is_some()
        {
            return Self::LocalTransportStatus(code);
        }
        let message = match status.message() {
            "RUNTIME_PEER_INVALID_POLICY" => "RUNTIME_PEER_INVALID_POLICY",
            "RUNTIME_PEER_INVALID_SELECTOR" => "RUNTIME_PEER_INVALID_SELECTOR",
            "RUNTIME_PEER_UNAUTHENTICATED" => "RUNTIME_PEER_UNAUTHENTICATED",
            "RUNTIME_PEER_DENIED" => "RUNTIME_PEER_DENIED",
            "RUNTIME_PEER_POLICY_NOT_CURRENT" => "RUNTIME_PEER_POLICY_NOT_CURRENT",
            "RUNTIME_PEER_CLOCK_UNAVAILABLE" => "RUNTIME_PEER_CLOCK_UNAVAILABLE",
            _ => "TEST_UNEXPECTED_RPC_STATUS_REDACTED",
        };
        Self::Rpc(code, message.into())
    }

    pub fn application(self, code: Code, detail: &str) {
        match self {
            Self::Rpc(actual, message) => {
                assert_eq!(actual, code);
                assert_eq!(message, detail);
                assert!(!message.contains("canary") && message.len() <= 128);
            }
            Self::Transport | Self::LocalTransportStatus(_) => {
                panic!("pair refusal must reach the handler over real TLS")
            }
        }
    }
    pub fn transport(self, before: (usize, usize), after: (usize, usize)) {
        assert_eq!(
            after, before,
            "this TLS negative must dispatch zero pair calls"
        );
        assert!(
            matches!(
                self,
                Self::Transport | Self::LocalTransportStatus(Code::Unknown | Code::Unavailable)
            ),
            "application/deadline errors do not prove TLS refusal"
        );
    }
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(8), future)
        .await
        .expect("pair test watchdog expired; timeout is not a successful refusal")
}

pub async fn invoke(
    pki: &Pki,
    endpoint: &str,
    caller: Option<(&str, &str)>,
    query: Query<'_>,
) -> Result<(), Failure> {
    within(async {
        let mut tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")));
        if let Some((tree, leaf)) = caller {
            tls = tls.identity(pki.identity(tree, leaf));
        }
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_timeout(CONNECT)
            .timeout(RPC);
        let connect_started = Instant::now();
        let connected = tokio::time::timeout(CONNECT, endpoint.connect())
            .await
            .expect("TLS connect timeout is not a successful refusal");
        assert!(
            connect_started.elapsed() < CONNECT,
            "elapsed TLS deadline is not a successful refusal"
        );
        let channel = connected.map_err(|_| Failure::Transport)?;
        let mut client = RuntimeAuthorityServiceClient::new(channel)
            .max_decoding_message_size(4096)
            .max_encoding_message_size(4096);
        let mut request = Request::new(CheckRuntimeAuthorityRequest {
            schema_version: 1,
            target: Some(RuntimeTarget {
                workspace_id: query.workspace.into(),
                namespace_id: query.namespace.into(),
                proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
                revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
                generation: 1,
                fencing_token: 1,
            }),
            operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
            command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
            action: RuntimeAuthorityAction::CheckCurrentOperation as i32,
            installation_id: query.installation.into(),
            observed_controller_certificate_sha256: query.observed.to_vec(),
        });
        request.set_timeout(RPC);
        if query.spoof {
            for name in [
                "authorization",
                "x-runtime-role",
                "x-runtime-identity",
                "x-peer-certificate-sha256",
                "x-forwarded-client-cert",
            ] {
                request
                    .metadata_mut()
                    .insert(name, "pair-agent-spoof-canary".parse().unwrap());
            }
        }
        let rpc_started = Instant::now();
        let reply = tokio::time::timeout(RPC, client.check_runtime_authority(request))
            .await
            .expect("pair RPC timeout is not a successful refusal");
        assert!(
            rpc_started.elapsed() < RPC,
            "elapsed RPC deadline is not a successful refusal"
        );
        match reply {
            Err(status) if status.code() == Code::Unimplemented && status.message() == CHECKED => {
                Ok(())
            }
            Err(status) => Err(Failure::rpc(status)),
            Ok(_) => panic!("test pair listener must never fabricate a PG authority snapshot"),
        }
    })
    .await
}

pub async fn positive(pki: &Pki, endpoint: &str) -> Result<(), Failure> {
    invoke(
        pki,
        endpoint,
        Some(("trusted-host", AGENT)),
        Query::valid(pki),
    )
    .await
}
