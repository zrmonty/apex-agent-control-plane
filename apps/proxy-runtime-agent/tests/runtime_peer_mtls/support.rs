//! Existing disposable PKI only. No generation, writes or production identity.

use apex_proxy_runtime_agent::proto::{self, proxy_runtime_agent_client::ProxyRuntimeAgentClient};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tonic::{
    Code, Request,
    transport::{Certificate, ClientTlsConfig, Endpoint, Identity},
};

pub const INSTALL_A: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub const INSTALL_B: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
pub const CONTROLLER: &str = "control-operator-client";
pub const AGENT: &str = "agent-workload-client";
pub const UNKNOWN: &str = "ingest-http-client";
pub const CONNECT: Duration = Duration::from_secs(2);
pub const RPC: Duration = Duration::from_secs(2);
pub const ACK: &str = "PEER_POLICY_CHECKED_NOT_RUNTIME_AUTHORITY";

pub struct Pki {
    root: PathBuf,
}

impl Pki {
    pub fn require() -> Self {
        let root = std::env::var_os("APEX_BROWSER_TEST_PKI_DIR")
            .filter(|value| !value.is_empty())
            .expect("APEX_BROWSER_TEST_PKI_DIR is required for runtime_peer_mtls; no fixture skip");
        let root = PathBuf::from(root)
            .canonicalize()
            .expect("existing PKI directory required");
        assert!(root.is_dir(), "PKI root must be a directory");
        let pki = Self { root };
        assert_ne!(
            pki.read("trusted-host", "ca.pem"),
            pki.read("untrusted-host", "ca.pem"),
            "independently generated CA fixtures required"
        );
        for (tree, names) in [
            (
                "trusted-host",
                &[
                    "control-plane-server.pem",
                    "control-plane-server.key",
                    "control-operator-client.pem",
                    "control-operator-client.key",
                    "agent-workload-client.pem",
                    "agent-workload-client.key",
                    "ingest-http-client.pem",
                    "ingest-http-client.key",
                ][..],
            ),
            (
                "untrusted-host",
                &["control-operator-client.pem", "control-operator-client.key"][..],
            ),
        ] {
            for name in names {
                pki.require_file(tree, name);
            }
        }
        assert_ne!(
            pki.pin(CONTROLLER),
            pki.pin(AGENT),
            "roles need distinct trusted leaves"
        );
        assert_ne!(
            pki.pin(CONTROLLER),
            pki.pin(UNKNOWN),
            "unknown-pin control needs a distinct leaf"
        );
        pki
    }

    fn require_file(&self, tree: &str, name: &str) {
        let metadata = std::fs::metadata(self.root.join(tree).join(name)).expect(
            "required existing runtime TLS fixture missing; do not overwrite/regenerate it",
        );
        assert!(
            metadata.is_file() && (1..=1_048_576).contains(&metadata.len()),
            "invalid PKI fixture size/type"
        );
    }

    pub fn read(&self, tree: &str, name: &str) -> Vec<u8> {
        self.require_file(tree, name);
        let bytes = std::fs::read(self.root.join(tree).join(name))
            .expect("cannot read existing PKI fixture");
        assert!(
            (1..=1_048_576).contains(&bytes.len()),
            "PKI fixture changed size"
        );
        bytes
    }

    pub fn pin(&self, leaf: &str) -> String {
        let pem = self.read("trusted-host", &format!("{leaf}.pem"));
        let text = std::str::from_utf8(&pem).expect("test certificate must be PEM");
        assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert_eq!(text.matches("-----END CERTIFICATE-----").count(), 1);
        let encoded: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = STANDARD
            .decode(encoded)
            .expect("test certificate must contain DER");
        format!("{:x}", Sha256::digest(der))
    }

    pub fn identity(&self, tree: &str, leaf: &str) -> Identity {
        Identity::from_pem(
            self.read(tree, &format!("{leaf}.pem")),
            self.read(tree, &format!("{leaf}.key")),
        )
    }
}

pub fn now_us() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock before epoch")
            .as_micros(),
    )
    .expect("test clock overflow")
}

pub fn policy_document(pki: &Pki) -> Value {
    let now = now_us();
    json!({
        "schemaVersion": 1, "version": "tls-policy-1",
        "validFromUnixUs": now.checked_sub(60_000_000).unwrap().to_string(),
        "expiresAtUnixUs": now.checked_add(60_000_000).unwrap().to_string(),
        "peers": [
            {"certificateSha256": pki.pin(CONTROLLER), "identityId": "test-controller",
                "role": "controller", "revoked": false,
                "grants": [{"installationId": INSTALL_A, "workspaceId": "work", "namespaceId": "ns"},
                    {"installationId": INSTALL_B, "workspaceId": "other", "namespaceId": "space"}]},
            {"certificateSha256": pki.pin(AGENT), "identityId": "test-agent",
                "role": "agent", "revoked": false,
                "grants": [{"installationId": INSTALL_A, "workspaceId": "work", "namespaceId": "ns"}]}
        ]
    })
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(8), future)
        .await
        .expect("runtime peer component watchdog expired; timeout is not successful refusal")
}

#[derive(Clone, Copy)]
pub enum Method {
    Controller,
    Agent,
}

pub struct Query<'a> {
    pub installation: &'a str,
    pub workspace: &'a str,
    pub namespace: &'a str,
    pub spoof_identity: bool,
}

impl Default for Query<'_> {
    fn default() -> Self {
        Self {
            installation: INSTALL_A,
            workspace: "work",
            namespace: "ns",
            spoof_identity: false,
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Transport,
    Rpc(Code, String),
}

impl Failure {
    pub fn assert_application(self, code: Code, message: &str) {
        match self {
            Self::Rpc(actual_code, actual_message) => {
                assert_eq!(actual_code, code);
                assert_eq!(actual_message, message);
            }
            Self::Transport => panic!("expected application refusal after successful TLS"),
        }
    }

    pub fn assert_transport(self) {
        if let Self::Rpc(code, _) = self {
            assert_ne!(
                code,
                Code::DeadlineExceeded,
                "a timeout does not prove TLS refusal"
            );
            assert_ne!(
                code,
                Code::PermissionDenied,
                "application denial is not TLS refusal"
            );
            assert_ne!(
                code,
                Code::FailedPrecondition,
                "policy error is not TLS refusal"
            );
        }
    }
}

pub async fn invoke(
    pki: &Pki,
    endpoint: &str,
    client_identity: Option<(&str, &str)>,
    method: Method,
    query: Query<'_>,
) -> Result<(), Failure> {
    within(async {
        let mut tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")));
        if let Some((tree, leaf)) = client_identity {
            tls = tls.identity(pki.identity(tree, leaf));
        }
        let endpoint = Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .timeout(RPC);
        let channel = tokio::time::timeout(CONNECT, endpoint.connect())
            .await
            .expect("TLS connect timeout is not successful refusal")
            .map_err(|_| Failure::Transport)?;
        let mut client = ProxyRuntimeAgentClient::new(channel)
            .max_decoding_message_size(4096)
            .max_encoding_message_size(4096);
        let target = proto::RuntimeTarget {
            workspace_id: query.workspace.into(),
            namespace_id: query.namespace.into(),
            proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
            revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            generation: 1,
            fencing_token: 1,
        };
        match method {
            Method::Controller => {
                let reply = client
                    .inspect_runtime(request(target, &query))
                    .await
                    .map_err(|s| Failure::Rpc(s.code(), s.message().to_owned()))?
                    .into_inner();
                assert_eq!(reply.state, ACK);
                assert!(!reply.ready && !reply.admitting && reply.runtime_id.is_empty());
                assert!(
                    reply.readiness.is_none(),
                    "identity check must not manufacture readiness"
                );
            }
            Method::Agent => {
                let reply = client
                    .probe_upstream(request(
                        proto::ProbeUpstreamRequest {
                            target: Some(target),
                            upstream_id: "test-no-probe".into(),
                        },
                        &query,
                    ))
                    .await
                    .map_err(|s| Failure::Rpc(s.code(), s.message().to_owned()))?
                    .into_inner();
                assert!(
                    !reply.connected
                        && reply.catalog_hash.is_empty()
                        && reply.server_identity.is_empty()
                );
                assert_eq!(reply.error_code, ACK);
            }
        }
        Ok(())
    })
    .await
}

fn request<T>(body: T, query: &Query<'_>) -> Request<T> {
    let mut request = Request::new(body);
    request.set_timeout(RPC);
    // Test-only selector because the unchanged RuntimeTarget has no installation
    // field. This is a claim checked against a grant, never identity evidence.
    request.metadata_mut().insert(
        "x-test-installation-id",
        query.installation.parse().unwrap(),
    );
    if query.spoof_identity {
        for name in [
            "x-peer-certificate-sha256",
            "x-runtime-identity",
            "x-runtime-role",
            "x-forwarded-client-cert",
            "authorization",
        ] {
            request
                .metadata_mut()
                .insert(name, "spoofed-controller-canary".parse().unwrap());
        }
    }
    request
}
