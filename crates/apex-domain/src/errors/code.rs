#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayErrorCode {
    Unauthenticated,
    InvalidAuthorization,
    ScopeDenied,
    InvalidEventId,
    InvalidEnvelope,
    InvalidStructure,
    SecretExposure,
    InvalidTimestamp,
    InvalidIntegrity,
    PayloadTooLarge,
    IdempotencyCapacity,
    IdempotencyInProgress,
    RateLimited,
    AdmissionBusy,
    PublishFailed,
    Internal,
    SubjectTooLong,
    InvalidRetryConfiguration,
    InvalidNatsConfiguration,
    InvalidNatsPublishRequest,
    NatsConnectionFailed,
    IdempotencyConflict,
    InvalidSinkConfiguration,
    InvalidOutboxConfiguration,
    InvalidIdempotencyConfiguration,
}

impl GatewayErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::InvalidAuthorization => "INVALID_AUTHORIZATION_METADATA",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::InvalidEventId => "INVALID_EVENT_ID",
            Self::InvalidEnvelope => "INVALID_ENVELOPE",
            Self::InvalidStructure => "INVALID_ENVELOPE_STRUCTURE",
            Self::SecretExposure => "SECRET_EXPOSURE",
            Self::InvalidTimestamp => "INVALID_TIMESTAMP",
            Self::InvalidIntegrity => "INVALID_INTEGRITY",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::IdempotencyCapacity => "IDEMPOTENCY_CAPACITY",
            Self::IdempotencyInProgress => "IDEMPOTENCY_IN_PROGRESS",
            Self::RateLimited => "RATE_LIMITED",
            Self::AdmissionBusy => "ADMISSION_BUSY",
            Self::PublishFailed => "PUBLISH_FAILED",
            Self::Internal => "INTERNAL_FAILURE",
            Self::SubjectTooLong => "JETSTREAM_SUBJECT_TOO_LONG",
            Self::InvalidRetryConfiguration => "INVALID_RETRY_CONFIGURATION",
            Self::InvalidNatsConfiguration => "INVALID_NATS_CONFIGURATION",
            Self::InvalidNatsPublishRequest => "INVALID_NATS_PUBLISH_REQUEST",
            Self::NatsConnectionFailed => "NATS_CONNECTION_FAILED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::InvalidSinkConfiguration => "INVALID_SINK_CONFIGURATION",
            Self::InvalidOutboxConfiguration => "INVALID_OUTBOX_CONFIGURATION",
            Self::InvalidIdempotencyConfiguration => "INVALID_IDEMPOTENCY_CONFIGURATION",
        }
    }

    /// Code safe to expose in an external diagnostic handoff. Authentication
    /// parsing details and internal admission causes intentionally collapse to
    /// the transport-level family.
    pub fn public_code(self) -> &'static str {
        match self {
            Self::Unauthenticated | Self::InvalidAuthorization => "UNAUTHENTICATED",
            Self::RateLimited | Self::AdmissionBusy => "RESOURCE_EXHAUSTED",
            _ => self.as_str(),
        }
    }
}

