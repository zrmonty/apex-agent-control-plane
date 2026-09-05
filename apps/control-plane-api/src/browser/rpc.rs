//! Typed management boundary. This module grants no scope or runtime authority.
//! Browser headers are never copied to the internal management request.

use super::errors::BrowserError;
use crate::{contract_json::decode_management_json, proto};
use axum::http::{HeaderMap, header};
use prost::Message;
use serde::Serialize;

mod credential;
pub use credential::OperatorAccess;
mod transport;
pub use transport::{ManagementBridge, ManagementTransportConfig};

pub const MAX_RPC_JSON_BYTES: usize = 256 * 1024;
pub const MAX_RPC_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RpcDescriptor {
    pub service: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub input: &'static str,
    pub output: &'static str,
}

pub struct ManagementRequest {
    inner: RpcInput,
}

impl ManagementRequest {
    pub fn decode(path: &str, headers: &HeaderMap, body: &[u8]) -> Result<Self, BrowserError> {
        if !descriptors().iter().any(|entry| entry.path == path) {
            return Err(BrowserError::NotFound);
        }
        check_content_type(headers)?;
        if body.len() > MAX_RPC_JSON_BYTES {
            return Err(BrowserError::PayloadTooLarge);
        }
        let inner = RpcInput::decode(path, body)?;
        if inner.encoded_len() > crate::MAX_CONTROL_REQUEST_BYTES {
            return Err(BrowserError::PayloadTooLarge);
        }
        Ok(Self { inner })
    }

    pub fn descriptor(&self) -> &'static RpcDescriptor {
        self.inner.descriptor()
    }
}

impl std::fmt::Debug for ManagementRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementRequest")
            .field("method", &self.descriptor().method)
            .finish_non_exhaustive()
    }
}

macro_rules! descriptor {
    ($method:ident, $input:ident, $output:ident) => {
        RpcDescriptor {
            service: "apex.v1.McpProxyService",
            method: stringify!($method),
            path: concat!("/api/apex/v1/McpProxyService/", stringify!($method)),
            input: concat!("apex.v1.", stringify!($input)),
            output: concat!("apex.v1.", stringify!($output)),
        }
    };
}

// One table binds the literal route, generated input/output types and tonic
// method. Tests compare every entry to the generated browser allowlist.
macro_rules! management_rpcs {
    ($(($method:ident, $input:ident, $output:ident, $handler:ident)),+ $(,)?) => {
        enum RpcInput { $($method(Box<proto::$input>)),+ }
        impl RpcInput {
            fn decode(path: &str, body: &[u8]) -> Result<Self, BrowserError> {
                match path {
                    $(concat!("/api/apex/v1/McpProxyService/", stringify!($method)) =>
                        decode_management_json(body).map(|input| Self::$method(Box::new(input)))
                            .map_err(|_| BrowserError::InvalidRequest),)+
                    _ => Err(BrowserError::NotFound),
                }
            }
            fn descriptor(&self) -> &'static RpcDescriptor {
                match self { $(Self::$method(_) => &descriptor!($method, $input, $output)),+ }
            }
            fn encoded_len(&self) -> usize {
                match self { $(Self::$method(input) => input.encoded_len()),+ }
            }
            async fn forward(
                self,
                mut client: proto::mcp_proxy_service_client::McpProxyServiceClient<tonic::transport::Channel>,
                access: &OperatorAccess,
                timeout: std::time::Duration,
            ) -> Result<Vec<u8>, BrowserError> {
                match self {
                    $(Self::$method(input) => {
                        let response: proto::$output = client.$handler(access.request(*input, timeout)?)
                            .await.map_err(|status| BrowserError::from_status(&status))?.into_inner();
                        encode_response(&response)
                    }),+
                }
            }
        }
        pub fn descriptors() -> &'static [RpcDescriptor] {
            &[$(descriptor!($method, $input, $output)),+]
        }
    };
}

management_rpcs! {
    (CreateProxy, CreateProxyRequest, CreateProxyResponse, create_proxy),
    (DecideProxyApproval, DecideProxyApprovalRequest, DecideProxyApprovalResponse, decide_proxy_approval),
    (DeployProxy, DeployProxyRequest, DeployProxyResponse, deploy_proxy),
    (DiscoverUpstream, DiscoverUpstreamRequest, DiscoverUpstreamResponse, discover_upstream),
    (GetProxy, GetProxyRequest, GetProxyResponse, get_proxy),
    (GetProxyCapabilities, GetProxyCapabilitiesRequest, GetProxyCapabilitiesResponse, get_proxy_capabilities),
    (GetProxyOperation, GetProxyOperationRequest, GetProxyOperationResponse, get_proxy_operation),
    (GetProxyTrace, GetProxyTraceRequest, GetProxyTraceResponse, get_proxy_trace),
    (ListProxies, ListProxiesRequest, ListProxiesResponse, list_proxies),
    (ListProxyActivity, ListProxyActivityRequest, ListProxyActivityResponse, list_proxy_activity),
    (ListProxyApprovals, ListProxyApprovalsRequest, ListProxyApprovalsResponse, list_proxy_approvals),
    (ListProxyBindings, ListProxyBindingsRequest, ListProxyBindingsResponse, list_proxy_bindings),
    (ListProxyRevisions, ListProxyRevisionsRequest, ListProxyRevisionsResponse, list_proxy_revisions),
    (PauseProxy, PauseProxyRequest, PauseProxyResponse, pause_proxy),
    (PublishProxyRevision, PublishProxyRevisionRequest, PublishProxyRevisionResponse, publish_proxy_revision),
    (ResumeProxy, ResumeProxyRequest, ResumeProxyResponse, resume_proxy),
    (RetireProxy, RetireProxyRequest, RetireProxyResponse, retire_proxy),
    (RollbackProxy, RollbackProxyRequest, RollbackProxyResponse, rollback_proxy),
    (RotateProxyCredentials, RotateProxyCredentialsRequest, RotateProxyCredentialsResponse, rotate_proxy_credentials),
    (TestProxyConnection, TestProxyConnectionRequest, TestProxyConnectionResponse, test_proxy_connection),
    (UpdateProxyDraft, UpdateProxyDraftRequest, UpdateProxyDraftResponse, update_proxy_draft),
    (ValidateProxy, ValidateProxyRequest, ValidateProxyResponse, validate_proxy),
}

fn check_content_type(headers: &HeaderMap) -> Result<(), BrowserError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(BrowserError::UnsupportedMediaType)?;
    if values.next().is_some() || headers.contains_key(header::CONTENT_ENCODING) || value.len() > 64
    {
        return Err(BrowserError::UnsupportedMediaType);
    }
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(BrowserError::UnsupportedMediaType);
    }
    if let Some(charset) = parts.next() {
        let Some((name, value)) = charset.trim().split_once('=') else {
            return Err(BrowserError::UnsupportedMediaType);
        };
        if !name.trim().eq_ignore_ascii_case("charset")
            || !value.trim().eq_ignore_ascii_case("utf-8")
            || parts.next().is_some()
        {
            return Err(BrowserError::UnsupportedMediaType);
        }
    }
    Ok(())
}

pub fn encode_response<T: Serialize>(response: &T) -> Result<Vec<u8>, BrowserError> {
    let mut output = BoundedJson(Vec::with_capacity(4096));
    serde_json::to_writer(&mut output, response).map_err(|_| BrowserError::Unavailable)?;
    Ok(output.0)
}

struct BoundedJson(Vec<u8>);
impl std::io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_RPC_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "management response exceeds byte ceiling",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod forwarding_tests;
#[cfg(test)]
mod tests;
