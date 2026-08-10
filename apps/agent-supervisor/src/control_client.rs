//! The supervisor's own `PollCommands`/`AckCommand` client.
//!
//! Structurally the Rust sibling of `packages/sdk-python/src/apex_sdk/control_transport.py`'s
//! `GrpcControlTransport`: mTLS channel, bearer token in the `authorization`
//! metadata, and nothing else on the wire. The credential this client
//! authenticates with is the supervisor's **own**, distinct workload
//! identity -- see `crate::credentials` and this crate's docs -- never the
//! agent's.

use crate::proto;

#[derive(Debug)]
pub struct ControlClientError(tonic::Status);

impl std::fmt::Display for ControlClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control gateway call failed: {}", self.0)
    }
}

impl std::error::Error for ControlClientError {}

impl From<tonic::Status> for ControlClientError {
    fn from(status: tonic::Status) -> Self {
        Self(status)
    }
}

/// A connected client authenticated as the supervisor's own workload
/// identity.
pub struct ControlClient {
    inner: proto::control_gateway_client::ControlGatewayClient<tonic::transport::Channel>,
    /// Validated (non-empty, printable ASCII, no whitespace) at credential
    /// load time by `crate::credentials::read_token_file`, so building the
    /// `authorization` header value here cannot fail.
    authorization_header: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
}

impl ControlClient {
    /// Connects over mTLS to `endpoint` (`host:port`, no scheme) using the
    /// supervisor's own certificate/key/CA, and binds the bearer `token` to
    /// every call this client makes.
    pub async fn connect(
        endpoint: &str,
        server_ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        token: &str,
    ) -> Result<Self, tonic::transport::Error> {
        let tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(server_ca_pem))
            .identity(tonic::transport::Identity::from_pem(client_cert_pem, client_key_pem));
        let channel = tonic::transport::Channel::from_shared(format!("https://{endpoint}"))
            .expect("endpoint was already validated as a bare host:port authority")
            .tls_config(tls)?
            .connect()
            .await?;
        let authorization_header = format!("Bearer {token}")
            .parse()
            .expect("token was validated as printable ASCII with no whitespace at load time");
        Ok(Self {
            inner: proto::control_gateway_client::ControlGatewayClient::new(channel),
            authorization_header,
        })
    }

    fn authorize<T>(&self, body: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(body);
        request
            .metadata_mut()
            .insert("authorization", self.authorization_header.clone());
        request
    }

    /// Retrieves the commands pending for the supervisor's own bound
    /// identity. In ordinary operation this returns `force_stop` or nothing;
    /// any other action reaching this path is logged and acknowledged away
    /// by the caller in `main.rs` rather than enacted -- this client itself
    /// does not interpret actions.
    pub async fn poll(&mut self, max_commands: u32) -> Result<proto::PollCommandsResponse, ControlClientError> {
        let request = self.authorize(proto::PollCommandsRequest { max_commands });
        Ok(self.inner.poll_commands(request).await?.into_inner())
    }

    pub async fn ack(
        &mut self,
        command: &proto::PendingControlCommand,
    ) -> Result<proto::AckCommandResponse, ControlClientError> {
        let request = self.authorize(proto::AckCommandRequest {
            workspace_id: command.workspace_id.clone(),
            namespace_id: command.namespace_id.clone(),
            command_id: command.command_id.clone(),
            delivery_attempt: command.delivery_attempt,
        });
        Ok(self.inner.ack_command(request).await?.into_inner())
    }
}
