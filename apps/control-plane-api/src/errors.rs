//! Redacted control-gateway errors. Mirrors the `event-ingest` `GatewayError`
//! shape (a stable public code plus a static, review-approved message) so
//! diagnostics stay safe to hand to an operator or an AI assistant: no raw
//! transport errors, credentials, or command payload content ever land here.

use apex_event_ingest::{GatewayError, GatewayErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorCode {
    Unauthenticated,
    InvalidAuthorization,
    /// The gateway could not *check* the credential, as distinct from having
    /// checked it and found it bad. Raised only by the Keycloak resolver, when
    /// its cached JWKS is absent or older than the configured staleness
    /// ceiling. Kept separate from `Unauthenticated` on purpose: an operator
    /// holding a perfectly good token during an identity-provider outage
    /// should be told the verifier is down, not that they are unauthenticated
    /// -- otherwise the obvious debugging move is to start weakening the
    /// credential path. It leaks nothing an attacker does not learn anyway by
    /// watching every request fail identically.
    CredentialVerifierUnavailable,
    ScopeDenied,
    RateLimited,
    InvalidCommand,
    IdempotencyConflict,
    IdempotencyInProgress,
    Capacity,
    Internal,
    /// A `CancelCommand` targeted a command that has already been delivered
    /// at least once. Refused rather than attempted: the agent may already be
    /// acting on it, and cancelling it out from under a delivery would
    /// recreate exactly the "did the agent get it or not" ambiguity the
    /// inbox's whole delivery-tracking design exists to eliminate. Distinct
    /// from `InvalidCommand` -- the request is well-formed -- and from
    /// `IdempotencyConflict` -- there is no field mismatch. The remedy is
    /// different too: issue a new command, do not retry this one.
    AlreadyDelivered,
}

impl CommandErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::InvalidAuthorization => "INVALID_AUTHORIZATION_METADATA",
            Self::CredentialVerifierUnavailable => "CREDENTIAL_VERIFIER_UNAVAILABLE",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::RateLimited => "RATE_LIMITED",
            Self::InvalidCommand => "INVALID_COMMAND",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyInProgress => "IDEMPOTENCY_IN_PROGRESS",
            Self::Capacity => "OUTBOX_CAPACITY",
            Self::Internal => "INTERNAL_FAILURE",
            Self::AlreadyDelivered => "ALREADY_DELIVERED",
        }
    }

    fn grpc_code(self) -> tonic::Code {
        match self {
            Self::Unauthenticated | Self::InvalidAuthorization => tonic::Code::Unauthenticated,
            // `Unavailable`, not `Unauthenticated`: this is retryable and the
            // caller's credential may well be fine.
            Self::CredentialVerifierUnavailable => tonic::Code::Unavailable,
            Self::ScopeDenied => tonic::Code::PermissionDenied,
            Self::RateLimited | Self::Capacity => tonic::Code::ResourceExhausted,
            Self::InvalidCommand | Self::IdempotencyConflict => tonic::Code::InvalidArgument,
            Self::IdempotencyInProgress => tonic::Code::Aborted,
            Self::Internal => tonic::Code::Internal,
            // The request was well-formed and the identity was found; the
            // gateway's *state* just does not permit this operation anymore.
            // That is precisely what FAILED_PRECONDITION means, and it is
            // distinct from the InvalidArgument codes above.
            Self::AlreadyDelivered => tonic::Code::FailedPrecondition,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub code: CommandErrorCode,
    message: &'static str,
}

impl CommandError {
    pub fn new(code: CommandErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    /// The static, review-approved message alone, without the `CODE: `
    /// prefix [`Self::into_status`] adds. Exists for callers that report a
    /// `code` and a `message` as two separate structured fields rather than
    /// one gRPC status string -- `SubmitBulkCommand`'s per-target
    /// `BulkCommandResult` is the first of these, and any future RPC that
    /// reports one error per item (rather than one error per call) should
    /// reuse this rather than re-deriving the message from `into_status`'s
    /// formatted string.
    pub fn message(&self) -> &'static str {
        self.message
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            CommandErrorCode::Unauthenticated,
            "The control gateway rejected an unauthenticated caller. Supply a valid operator credential.",
        )
    }

    pub fn invalid_authorization() -> Self {
        Self::new(
            CommandErrorCode::InvalidAuthorization,
            "Send exactly one ASCII authorization header using the form Bearer <token>.",
        )
    }

    pub fn scope_denied() -> Self {
        Self::new(
            CommandErrorCode::ScopeDenied,
            "The authenticated operator is not permitted to issue commands in this workspace/namespace.",
        )
    }

    /// The credential could not be checked. See
    /// [`CommandErrorCode::CredentialVerifierUnavailable`].
    pub fn credential_verifier_unavailable() -> Self {
        Self::new(
            CommandErrorCode::CredentialVerifierUnavailable,
            "The control gateway cannot currently verify operator credentials. Retry with backoff.",
        )
    }

    pub fn rate_limited() -> Self {
        Self::new(
            CommandErrorCode::RateLimited,
            "The control gateway is temporarily rate-limited. Retry with backoff.",
        )
    }

    pub fn invalid_command() -> Self {
        Self::new(
            CommandErrorCode::InvalidCommand,
            "The command was malformed: check the command identity and delivery fields.",
        )
    }

    /// See [`CommandErrorCode::AlreadyDelivered`].
    pub fn already_delivered() -> Self {
        Self::new(
            CommandErrorCode::AlreadyDelivered,
            "This command has already been delivered to its agent at least once and can no longer be cancelled: the agent may already be acting on it. Issue a new command instead.",
        )
    }

    pub fn internal() -> Self {
        Self::new(
            CommandErrorCode::Internal,
            "The control gateway failed to process the request.",
        )
    }

    /// Maps a `GatewayError` raised by envelope validation or the outbox onto
    /// the control-gateway's own redacted taxonomy. `event-ingest`'s codes
    /// are intentionally not passed through verbatim: some (for example
    /// `Unauthenticated`) describe the ingest data-path identity model, which
    /// does not apply to an OOB operator command.
    pub fn from_gateway_error(error: &GatewayError) -> Self {
        let code = match error.code {
            GatewayErrorCode::IdempotencyConflict => CommandErrorCode::IdempotencyConflict,
            GatewayErrorCode::IdempotencyInProgress => CommandErrorCode::IdempotencyInProgress,
            GatewayErrorCode::IdempotencyCapacity => CommandErrorCode::Capacity,
            GatewayErrorCode::RateLimited | GatewayErrorCode::AdmissionBusy => {
                CommandErrorCode::RateLimited
            }
            GatewayErrorCode::Internal
            | GatewayErrorCode::PublishFailed
            | GatewayErrorCode::NatsConnectionFailed
            | GatewayErrorCode::InvalidOutboxConfiguration
            | GatewayErrorCode::InvalidIdempotencyConfiguration => CommandErrorCode::Internal,
            _ => CommandErrorCode::InvalidCommand,
        };
        let message = match code {
            CommandErrorCode::IdempotencyConflict => {
                "command_id was already accepted with different fields. Use a new command_id for a genuinely different command."
            }
            CommandErrorCode::IdempotencyInProgress => {
                "This command is currently being durably recorded by another request. Retry shortly."
            }
            CommandErrorCode::Capacity => {
                "The durable command outbox is at capacity. Retry after operator remediation."
            }
            CommandErrorCode::RateLimited => "The control gateway is temporarily rate-limited.",
            CommandErrorCode::Internal => "The control gateway failed to process the request.",
            _ => {
                "The command was malformed: check target identifiers, action, and required parameters for the requested action."
            }
        };
        Self::new(code, message)
    }

    pub fn into_status(self) -> tonic::Status {
        tonic::Status::new(
            self.code.grpc_code(),
            format!("{}: {}", self.code.as_str(), self.message),
        )
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}
