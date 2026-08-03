use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use prost::Message;

use crate::{Caller, EventPublisher, GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES, proto};

impl Caller {
    pub fn authenticated(
        subject: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            authenticated: true,
            subject: Some(subject.into()),
            bound_agent_id: None,
            allowed_scopes: allowed_scopes.into_iter().map(Into::into).collect(),
        }
    }

    /// Creates an authenticated caller whose workload identity is bound to a
    /// single agent identifier. The gateway enforces this binding before any
    /// event reaches a publisher.
    pub fn authenticated_for_agent(
        subject: impl Into<String>,
        agent_id: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            authenticated: true,
            subject: Some(subject.into()),
            bound_agent_id: Some(agent_id.into()),
            allowed_scopes: allowed_scopes.into_iter().map(Into::into).collect(),
        }
    }

    pub fn bound_agent_id(&self) -> Option<&str> {
        self.bound_agent_id.as_deref()
    }

    /// Stable workload identity for audit attribution. The value is never
    /// included in redacted diagnostics or event payloads.
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    pub fn anonymous() -> Self {
        Self {
            authenticated: false,
            subject: None,
            bound_agent_id: None,
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
    attempts: Arc<Mutex<(Instant, u32)>>,
}

const AUTH_ATTEMPTS_PER_SECOND: u32 = 120;

impl<R: BearerTokenResolver> BearerTokenVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
            attempts: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }
}

impl<R: BearerTokenResolver> CallerVerifier for BearerTokenVerifier<R> {
    fn verify(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Caller, GatewayError> {
        let mut attempts = self.attempts.lock().map_err(|_| GatewayError::internal())?;
        if attempts.0.elapsed() >= Duration::from_secs(1) {
            *attempts = (Instant::now(), 0);
        }
        attempts.1 = attempts.1.saturating_add(1);
        if attempts.1 > AUTH_ATTEMPTS_PER_SECOND {
            return Err(GatewayError::new(GatewayErrorCode::RateLimited));
        }
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
            || token
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(GatewayError::invalid_authorization());
        }
        self.resolver.resolve(token)
    }
}

pub struct AuthenticatedGrpcService<P: EventPublisher, V: CallerVerifier> {
    adapter: Arc<Mutex<crate::AuthenticatedIngestAdapter<P>>>,
    verifier: Arc<V>,
    blocking_limit: Arc<Semaphore>,
}

const MAX_BLOCKING_INGEST_TASKS: usize = 64;

impl<P: EventPublisher, V: CallerVerifier> AuthenticatedGrpcService<P, V> {
    pub fn new(adapter: crate::AuthenticatedIngestAdapter<P>, verifier: V) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            verifier: Arc::new(verifier),
            blocking_limit: Arc::new(Semaphore::new(MAX_BLOCKING_INGEST_TASKS)),
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
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            self.blocking_limit.clone().acquire_owned(),
        )
        .await
        .map_err(|_| GatewayError::new(GatewayErrorCode::RateLimited).grpc_status_value())?
        .map_err(|_| GatewayError::internal().grpc_status_value())?;
        let adapter = self.adapter.clone();
        let envelope = request.into_inner();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut adapter = adapter.lock().map_err(|_| GatewayError::internal())?;
            catch_unwind(AssertUnwindSafe(|| {
                adapter.ingest_envelope(&caller, envelope)
            }))
            .map_err(|_| GatewayError::internal())?
        })
        .await
        .map_err(|_| GatewayError::internal().grpc_status_value())?
        .map(tonic::Response::new)
        .map_err(|error| error.grpc_status_value())
    }
}
