use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use prost::Message;

use crate::{Caller, EventPublisher, GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES, proto};

impl Caller {
    pub fn authenticated(
        subject: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let _ = subject.into();
        Self {
            authenticated: true,
            allowed_scopes: allowed_scopes.into_iter().map(Into::into).collect(),
        }
    }

    pub fn anonymous() -> Self {
        Self {
            authenticated: false,
            allowed_scopes: std::collections::HashSet::new(),
        }
    }
}

/// Verifies transport credentials and returns an authorized caller scope.
pub trait CallerVerifier: Send + Sync + 'static {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError>;
}

/// Deployment-provided token validation and scope mapping.
pub trait BearerTokenResolver: Send + Sync + 'static {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError>;
}

pub struct BearerTokenVerifier<R: BearerTokenResolver> {
    resolver: Arc<R>,
}

impl<R: BearerTokenResolver> BearerTokenVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
        }
    }
}

impl<R: BearerTokenResolver> CallerVerifier for BearerTokenVerifier<R> {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        let mut values = metadata.get_all("authorization").iter();
        let value = values.next().ok_or_else(GatewayError::unauthenticated)?;
        if values.next().is_some() {
            return Err(GatewayError::invalid_authorization());
        }
        let value = value
            .to_str()
            .map_err(|_| GatewayError::invalid_authorization())?;
        let (scheme, token) = value
            .split_once(' ')
            .ok_or_else(GatewayError::invalid_authorization)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.len() > 4096
            || !token.is_ascii()
            || token.chars().any(char::is_whitespace)
        {
            return Err(GatewayError::invalid_authorization());
        }
        self.resolver.resolve(token)
    }
}

pub struct AuthenticatedGrpcService<P: EventPublisher, V: CallerVerifier> {
    adapter: Arc<Mutex<crate::AuthenticatedIngestAdapter<P>>>,
    verifier: Arc<V>,
}

impl<P: EventPublisher, V: CallerVerifier> AuthenticatedGrpcService<P, V> {
    pub fn new(adapter: crate::AuthenticatedIngestAdapter<P>, verifier: V) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            verifier: Arc::new(verifier),
        }
    }
}

pub fn bounded_event_ingest_server<P, V>(
    service: AuthenticatedGrpcService<P, V>,
) -> proto::event_ingest_server::EventIngestServer<AuthenticatedGrpcService<P, V>>
where
    P: EventPublisher + Send + 'static,
    V: CallerVerifier,
{
    proto::event_ingest_server::EventIngestServer::new(service)
        .max_decoding_message_size(MAX_ENVELOPE_BYTES)
}

#[tonic::async_trait]
impl<P, V> proto::event_ingest_server::EventIngest for AuthenticatedGrpcService<P, V>
where
    P: EventPublisher + Send + 'static,
    V: CallerVerifier,
{
    async fn ingest(
        &self,
        request: tonic::Request<proto::EventEnvelope>,
    ) -> Result<tonic::Response<proto::IngestResponse>, tonic::Status> {
        if request.get_ref().encoded_len() > MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge).grpc_status_value());
        }
        let caller = catch_unwind(AssertUnwindSafe(|| {
            self.verifier.verify(request.metadata())
        }))
        .map_err(|_| GatewayError::internal().grpc_status_value())?
        .map_err(|error| error.grpc_status_value())?;
        let mut adapter = self
            .adapter
            .lock()
            .map_err(|_| GatewayError::internal().grpc_status_value())?;
        catch_unwind(AssertUnwindSafe(|| {
            adapter.ingest_envelope(&caller, request.into_inner())
        }))
        .map_err(|_| GatewayError::internal().grpc_status_value())?
        .map(tonic::Response::new)
        .map_err(|error| error.grpc_status_value())
    }
}
