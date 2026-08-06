//! Redacted control-gateway errors. Mirrors the `event-ingest` `GatewayError`
//! shape (a stable public code plus a static, review-approved message) so
//! diagnostics stay safe to hand to an operator or an AI assistant: no raw
//! transport errors, credentials, or command payload content ever land here.

use apex_event_ingest::{GatewayError, GatewayErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorCode {
    Unauthenticated,
    InvalidAuthorization,
    ScopeDenied,
    RateLimited,
    InvalidCommand,
    IdempotencyConflict,
    IdempotencyInProgress,
    Capacity,
    Internal,
}

impl CommandErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::InvalidAuthorization => "INVALID_AUTHORIZATION_METADATA",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::RateLimited => "RATE_LIMITED",
            Self::InvalidCommand => "INVALID_COMMAND",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyInProgress => "IDEMPOTENCY_IN_PROGRESS",
            Self::Capacity => "OUTBOX_CAPACITY",
            Self::Internal => "INTERNAL_FAILURE",
        }
    }

    fn grpc_code(self) -> tonic::Code {
        match self {
            Self::Unauthenticated | Self::InvalidAuthorization => tonic::Code::Unauthenticated,
            Self::ScopeDenied => tonic::Code::PermissionDenied,
            Self::RateLimited | Self::Capacity => tonic::Code::ResourceExhausted,
            Self::InvalidCommand | Self::IdempotencyConflict => tonic::Code::InvalidArgument,
            Self::IdempotencyInProgress => tonic::Code::Aborted,
            Self::Internal => tonic::Code::Internal,
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

    pub fn rate_limited() -> Self {
        Self::new(
            CommandErrorCode::RateLimited,
            "The control gateway is temporarily rate-limited. Retry with backoff.",
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
