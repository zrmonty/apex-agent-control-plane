//! Bounded point-in-time authority observation; never an execution permit.

use std::{
    fmt,
    time::{Duration, Instant},
};

use apex_auth::{PeerIdentity, RuntimePeerError, RuntimePeerPolicy, RuntimePeerRole};
use tokio::sync::Semaphore;
use tonic::{
    Code, Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use crate::proto;
use proto::runtime_authority_service_client::RuntimeAuthorityServiceClient;

mod configuration;
mod snapshot;

const MAX_BUDGET: Duration = Duration::from_secs(5);
const CAPACITY: usize = 8;
const MESSAGE_LIMIT: usize = 4096;

/// Deployment-owned transport and enrolled metadata. Debug never exposes it.
pub struct AuthorityClientConfig {
    pub endpoint: String,
    pub tls_server_name: String,
    pub ca_pem: Vec<u8>,
    pub client_certificate_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub installation_id: String,
    pub agent_identity_id: String,
    pub enrollment_version: String,
    pub host_policy_version: String,
}

/// Borrowed operation claims; these are not authenticated by their shape.
pub struct AuthorityOperation<'a> {
    pub target: &'a proto::RuntimeTarget,
    pub operation_id: &'a str,
    pub command_id: &'a str,
    pub config_hash: &'a str,
}

/// One bounded authority connection, with no caller-selected channel constructor.
pub struct RuntimeAuthorityClient {
    client: RuntimeAuthorityServiceClient<Channel>,
    slots: Semaphore,
    // Transport fields are moved into tonic at connect; only enrollment metadata remains.
    config: AuthorityClientConfig,
}

/// Bounded, redacted refusals with no underlying error or response retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClientError {
    InvalidConfiguration,
    InvalidInput,
    Unauthenticated,
    Denied,
    Transport,
    Unavailable,
    Overloaded,
    Deadline,
    RemoteRefusal,
    InvalidSnapshot,
    MismatchedSnapshot,
}

impl AuthorityClientError {
    /// Stable code suitable for diagnostics without exposing transport details.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "RUNTIME_AUTHORITY_CLIENT_INVALID_CONFIGURATION",
            Self::InvalidInput => "RUNTIME_AUTHORITY_CLIENT_INVALID_INPUT",
            Self::Unauthenticated => "RUNTIME_AUTHORITY_CLIENT_UNAUTHENTICATED",
            Self::Denied => "RUNTIME_AUTHORITY_CLIENT_DENIED",
            Self::Transport => "RUNTIME_AUTHORITY_CLIENT_TRANSPORT",
            Self::Unavailable => "RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE",
            Self::Overloaded => "RUNTIME_AUTHORITY_CLIENT_OVERLOADED",
            Self::Deadline => "RUNTIME_AUTHORITY_CLIENT_DEADLINE",
            Self::RemoteRefusal => "RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL",
            Self::InvalidSnapshot => "RUNTIME_AUTHORITY_CLIENT_INVALID_SNAPSHOT",
            Self::MismatchedSnapshot => "RUNTIME_AUTHORITY_CLIENT_MISMATCHED_SNAPSHOT",
        }
    }
}

impl fmt::Display for AuthorityClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for AuthorityClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for AuthorityClientError {}

impl fmt::Debug for AuthorityClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorityClientConfig { [redacted] }")
    }
}

impl fmt::Debug for AuthorityOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorityOperation { [redacted] }")
    }
}

impl fmt::Debug for RuntimeAuthorityClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityClient { [redacted] }")
    }
}

impl RuntimeAuthorityClient {
    /// Establish deployment-pinned mTLS within one five-second bound.
    ///
    /// # Errors
    /// Refuses invalid configuration and unavailable or untrusted transport.
    pub async fn connect(mut config: AuthorityClientConfig) -> Result<Self, AuthorityClientError> {
        let started = Instant::now();
        let deadline = tokio::time::Instant::from_std(started + MAX_BUDGET);
        let result = tokio::time::timeout_at(deadline, async {
            configuration::validate(&config)?;
            // All PEM and metadata bounds were checked before any parser/copy.
            // Explicit roots only: no enabled/system roots, key logging or proxy environment.
            let tls = ClientTlsConfig::new()
                .domain_name(std::mem::take(&mut config.tls_server_name))
                .ca_certificate(Certificate::from_pem(std::mem::take(&mut config.ca_pem)))
                .identity(Identity::from_pem(
                    std::mem::take(&mut config.client_certificate_pem),
                    std::mem::take(&mut config.client_key_pem),
                ));
            let endpoint = Endpoint::from_shared(std::mem::take(&mut config.endpoint))
                .map_err(|_| AuthorityClientError::InvalidConfiguration)?
                .tls_config(tls)
                .map_err(|_| AuthorityClientError::InvalidConfiguration)?
                .buffer_size(CAPACITY)
                .concurrency_limit(CAPACITY);
            // Endpoint::connect awaits connection readiness; never use connect_lazy.
            let channel = endpoint
                .connect()
                .await
                .map_err(|_| AuthorityClientError::Transport)?;
            Ok(Self {
                client: RuntimeAuthorityServiceClient::new(channel)
                    .max_encoding_message_size(MESSAGE_LIMIT)
                    .max_decoding_message_size(MESSAGE_LIMIT),
                slots: Semaphore::new(CAPACITY),
                config,
            })
        })
        .await;
        // Tokio timeouts cannot preempt synchronous work or a last ready poll.
        if started.elapsed() >= MAX_BUDGET {
            return Err(AuthorityClientError::Deadline);
        }
        result.map_err(|_| AuthorityClientError::Deadline)?
    }

    /// Check this operation using actual inbound TLS and the caller's current policy.
    /// A returned snapshot is point-in-time evidence, not engine admission.
    ///
    /// # Errors
    /// Refuses invalid claims, unauthenticated peers, exhausted bounds and any
    /// remote refusal or invalid/mismatched snapshot.
    pub async fn check<T>(
        &self,
        incoming: &tonic::Request<T>,
        current_policy: &RuntimePeerPolicy,
        operation: AuthorityOperation<'_>,
        budget: Duration,
    ) -> Result<proto::RuntimeAuthoritySnapshot, AuthorityClientError> {
        let started = Instant::now();
        let budget = budget.min(MAX_BUDGET);
        if budget.is_zero() {
            return Err(AuthorityClientError::Deadline);
        }
        let deadline = tokio::time::Instant::from_std(started + budget);
        configuration::validate_operation(&operation)?;
        let authorize = || {
            current_policy
                .authorize(
                    incoming,
                    RuntimePeerRole::Controller,
                    &self.config.installation_id,
                    &operation.target.workspace_id,
                    &operation.target.namespace_id,
                )
                .map_err(peer_error)
        };
        let authenticated = authorize()?;
        let peer =
            PeerIdentity::from_request(incoming).ok_or(AuthorityClientError::Unauthenticated)?;
        // The shared ceiling covers readiness, request, decode, and final handoff.
        // A borrow permit drops on cancellation; there is no queued acquire/owner task.
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| AuthorityClientError::Overloaded)?;
        let mut client = self.client.clone();
        let mut request = Request::new(proto::CheckRuntimeAuthorityRequest {
            schema_version: 1,
            target: Some(operation.target.clone()),
            operation_id: operation.operation_id.into(),
            command_id: operation.command_id.into(),
            action: proto::RuntimeAuthorityAction::CheckCurrentOperation.into(),
            installation_id: self.config.installation_id.clone(),
            observed_controller_certificate_sha256: peer.certificate_sha256.to_vec(),
        });
        let remaining = budget
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AuthorityClientError::Deadline)?;
        request.set_timeout(remaining);
        // The generated method includes readiness and full unary decoding. Dropping
        // this future on timeout/caller cancellation drops the underlying RPC future.
        let result =
            tokio::time::timeout_at(deadline, client.check_runtime_authority(request)).await;
        if started.elapsed() >= budget {
            return Err(AuthorityClientError::Deadline);
        }
        let response = result
            .map_err(|_| AuthorityClientError::Deadline)?
            .map_err(remote_error)?
            .into_inner();
        // Recheck the very same original request and policy, not cached evidence or
        // outbound TLS. The owner supplies policy replacement on subsequent calls.
        let handoff = authorize()?;
        if handoff.identity_id() != authenticated.identity_id()
            || handoff.policy_version() != authenticated.policy_version()
        {
            return Err(AuthorityClientError::Denied);
        }
        snapshot::validate(
            &response,
            &self.config,
            &operation,
            handoff.identity_id(),
            handoff.policy_version(),
            started.elapsed(),
        )?;
        // Include validation/handoff work in both the request and lease interval bounds.
        let elapsed = started.elapsed();
        if elapsed >= budget {
            return Err(AuthorityClientError::Deadline);
        }
        snapshot::validate_elapsed(&response, elapsed)?;
        Ok(response)
    }
}

fn peer_error(error: RuntimePeerError) -> AuthorityClientError {
    match error {
        RuntimePeerError::Unauthenticated => AuthorityClientError::Unauthenticated,
        RuntimePeerError::InvalidSelector => AuthorityClientError::InvalidInput,
        RuntimePeerError::ClockUnavailable => AuthorityClientError::Unavailable,
        RuntimePeerError::InvalidPolicy
        | RuntimePeerError::Denied
        | RuntimePeerError::PolicyNotCurrent => AuthorityClientError::Denied,
    }
}

fn remote_error(status: tonic::Status) -> AuthorityClientError {
    // Inspect categories only; never retain/display a status, metadata or source.
    // Tonic's local grpc-timeout is Cancelled with a typed TimeoutExpired source.
    // Inspect a bounded chain without treating a remote cancellation string as time.
    let mut source = std::error::Error::source(&status);
    for _ in 0..8 {
        let Some(error) = source else {
            break;
        };
        if error.is::<tonic::TimeoutExpired>() {
            return AuthorityClientError::Deadline;
        }
        source = error.source();
    }
    match status.code() {
        Code::Unauthenticated => AuthorityClientError::Unauthenticated,
        Code::PermissionDenied => AuthorityClientError::Denied,
        Code::DeadlineExceeded => AuthorityClientError::Deadline,
        Code::Unavailable => AuthorityClientError::Unavailable,
        Code::Unknown if std::error::Error::source(&status).is_some() => {
            AuthorityClientError::Transport
        }
        _ => AuthorityClientError::RemoteRefusal,
    }
}
