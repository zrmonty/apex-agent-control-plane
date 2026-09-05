use apex_control_plane_api::{
    MAX_CONTROL_REQUEST_BYTES, OperatorCaller, StaticOperatorTokenResolver,
    browser::rpc::{
        ManagementBridge, ManagementRequest, ManagementTransportConfig, OperatorAccess,
    },
    proto::{self, mcp_proxy_service_client::McpProxyServiceClient},
};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{future::Future, path::PathBuf, time::Duration};
use tokio::task::JoinHandle;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

pub const TOKEN: &str = "browser-mtls-component-operator-credential";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const RPC_TIMEOUT: Duration = Duration::from_secs(2);
pub const TEST_SERVER_MESSAGE_LIMIT: usize = MAX_CONTROL_REQUEST_BYTES + 16 * 1024;
const WATCHDOG: Duration = Duration::from_secs(8);
const SERVER_NAME: &str = "control-plane-api";

pub struct Pki {
    root: PathBuf,
}

impl Pki {
    pub fn require() -> Self {
        let root = std::env::var_os("APEX_BROWSER_TEST_PKI_DIR")
            .filter(|value| !value.is_empty())
            .expect("APEX_BROWSER_TEST_PKI_DIR is required; generate fresh trusted/ and untrusted/ fixtures with deploy/compose/live-mtls/generate_pki.py (no skip)");
        let root = PathBuf::from(root)
            .canonicalize()
            .expect("APEX_BROWSER_TEST_PKI_DIR must name an existing fixture directory");
        assert!(
            root.is_dir(),
            "APEX_BROWSER_TEST_PKI_DIR must be a directory"
        );
        let pki = Self { root };
        assert_ne!(
            pki.trusted("ca.pem"),
            pki.untrusted("ca.pem"),
            "trusted and untrusted fixtures must have independently generated CAs"
        );
        pki
    }

    fn read(&self, tree: &str, name: &str) -> Vec<u8> {
        let path = self.root.join(tree).join(name);
        let metadata = std::fs::metadata(&path).unwrap_or_else(|_| {
            panic!(
                "missing PKI fixture {}; regenerate into a fresh owned directory",
                path.display()
            )
        });
        assert!(metadata.is_file() && (1..=1_048_576).contains(&metadata.len()));
        std::fs::read(&path)
            .unwrap_or_else(|_| panic!("cannot read PKI fixture {}", path.display()))
    }

    pub fn trusted(&self, name: &str) -> Vec<u8> {
        self.read("trusted-host", name)
    }

    pub fn untrusted(&self, name: &str) -> Vec<u8> {
        self.read("untrusted-host", name)
    }

    pub fn client_der(&self) -> Vec<u8> {
        let pem = self.trusted("control-operator-client.pem");
        let text = std::str::from_utf8(&pem).expect("client certificate must be PEM");
        let encoded: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD
            .decode(encoded)
            .expect("client certificate must contain valid DER")
    }

    pub fn config(&self, target: &str, rpc_timeout: Duration) -> ManagementTransportConfig {
        ManagementTransportConfig {
            target: target.to_owned(),
            server_name: SERVER_NAME.into(),
            ca_pem: self.trusted("ca.pem"),
            client_certificate_pem: self.trusted("control-operator-client.pem"),
            client_key_pem: Zeroizing::new(self.trusted("control-operator-client.key")),
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout,
            max_in_flight: 1,
        }
    }
}

pub fn resolver() -> StaticOperatorTokenResolver {
    StaticOperatorTokenResolver::new().with_token(
        TOKEN,
        OperatorCaller::scoped("operator:keycloak:browser-tls-component", ["work/ns"]).unwrap(),
    )
}

pub fn access() -> OperatorAccess {
    OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &resolver()).unwrap()
}

pub fn access_for(token: &str) -> OperatorAccess {
    let other = StaticOperatorTokenResolver::new().with_token(
        token,
        OperatorCaller::scoped("operator:other-edge-resolver", ["work/ns"]).unwrap(),
    );
    OperatorAccess::verify(Zeroizing::new(token.to_owned()), &other).unwrap()
}

pub fn decode(method: &str, body: &Value) -> ManagementRequest {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (header::CONTENT_TYPE, "application/json"),
        (header::AUTHORIZATION, "Bearer attacker-browser-header"),
        (header::COOKIE, "browser-cookie-must-not-be-forwarded"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert("x-apex-csrf", HeaderValue::from_static("browser-csrf"));
    headers.insert("x-operator-subject", HeaderValue::from_static("admin"));
    headers.insert(
        "x-forwarded-host",
        HeaderValue::from_static("attacker.invalid"),
    );
    ManagementRequest::decode(
        &format!("/api/apex/v1/McpProxyService/{method}"),
        &headers,
        &serde_json::to_vec(body).unwrap(),
    )
    .unwrap()
}

pub fn list_request() -> ManagementRequest {
    decode(
        "ListProxies",
        &json!({"workspaceId": "work", "namespaceId": "ns"}),
    )
}

pub fn list_input() -> proto::ListProxiesRequest {
    proto::ListProxiesRequest {
        workspace_id: "work".into(),
        namespace_id: "ns".into(),
        ..Default::default()
    }
}

pub fn raw_request<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    let mut value: tonic::metadata::MetadataValue<_> = format!("Bearer {TOKEN}").parse().unwrap();
    value.set_sensitive(true);
    request.metadata_mut().insert("authorization", value);
    request.set_timeout(RPC_TIMEOUT);
    request
}

pub async fn connect(pki: &Pki, target: &str, timeout: Duration) -> ManagementBridge {
    within(ManagementBridge::connect(pki.config(target, timeout)))
        .await
        .expect("production bridge must connect using the generated mTLS identity")
}

/// Independent controls only: no-certificate rejection and larger decoder.
/// All bridge assertions use ManagementBridge::connect, never from_channel.
pub async fn raw_client(
    pki: &Pki,
    target: &str,
    with_identity: bool,
) -> Result<McpProxyServiceClient<Channel>, tonic::transport::Error> {
    apex_control_plane_api::install_rustls_provider();
    let mut tls = ClientTlsConfig::new()
        .domain_name(SERVER_NAME)
        .ca_certificate(Certificate::from_pem(pki.trusted("ca.pem")));
    if with_identity {
        let key = Zeroizing::new(pki.trusted("control-operator-client.key"));
        tls = tls.identity(Identity::from_pem(
            pki.trusted("control-operator-client.pem"),
            key.as_slice(),
        ));
    }
    let channel = Endpoint::from_shared(target.to_owned())?
        .tls_config(tls)?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(RPC_TIMEOUT)
        .connect()
        .await?;
    Ok(McpProxyServiceClient::new(channel)
        .max_decoding_message_size(TEST_SERVER_MESSAGE_LIMIT)
        .max_encoding_message_size(MAX_CONTROL_REQUEST_BYTES))
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WATCHDOG, future)
        .await
        .expect("component operation exceeded the independent eight-second watchdog")
}

/// Retains cancellation ownership if a test panics or a watchdog expires.
pub struct TestTask<T>(Option<JoinHandle<T>>);

impl<T: Send + 'static> TestTask<T> {
    pub fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(future)))
    }

    pub async fn join(mut self) -> T {
        let outcome = within(self.0.as_mut().unwrap()).await;
        let _ = self.0.take();
        outcome.expect("component task panicked")
    }
}

impl<T> Drop for TestTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
