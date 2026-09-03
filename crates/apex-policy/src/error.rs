use thiserror::Error;

/// The semantic category of a validated governance identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentifierKind {
    /// A tool name such as `portfolio.read`.
    ToolName,
    /// An action name such as `read`.
    ActionName,
    /// A resource reference such as `portfolio:alpha`.
    ResourceName,
    /// A policy identity.
    PolicyId,
    /// A machine-readable policy reason code.
    ReasonCode,
    /// A backend identity.
    BackendName,
    /// A field path used by response filtering.
    FieldPath,
    /// A trace identifier.
    TraceId,
    /// A span identifier.
    SpanId,
    /// A run identifier.
    RunId,
    /// An Apex event identifier.
    EventId,
    /// A non-identifier input error.
    Unknown,
}

/// A content-free error raised while constructing a governance boundary value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GovernanceInputError {
    /// A workspace or namespace identifier is invalid.
    #[error("invalid governance scope")]
    InvalidScope,
    /// The caller is missing or fails the existing Apex caller invariants.
    #[error("invalid authenticated principal")]
    InvalidPrincipal,
    /// The caller does not hold the exact requested workspace/namespace scope.
    #[error("authenticated principal is not authorized for the requested scope")]
    ScopeNotAllowed,
    /// A bounded identifier contains invalid characters or exceeds its limit.
    #[error("invalid governance identifier")]
    InvalidIdentifier {
        /// The semantic identifier category that failed validation.
        kind: IdentifierKind,
    },
}

impl GovernanceInputError {
    /// Returns the identifier category for an identifier error.
    ///
    /// Non-identifier errors return [`IdentifierKind::Unknown`].
    pub fn kind(self) -> IdentifierKind {
        match self {
            Self::InvalidIdentifier { kind } => kind,
            Self::InvalidScope | Self::InvalidPrincipal | Self::ScopeNotAllowed => {
                IdentifierKind::Unknown
            }
        }
    }
}

/// A content-free operational failure returned by a governance adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GovernanceError {
    /// The authorization service could not make a decision.
    #[error("authorization service unavailable")]
    AuthorizationUnavailable,
    /// The policy service could not provide policy metadata.
    #[error("policy service unavailable")]
    PolicyUnavailable,
    /// Apex could not durably admit a tool execution event.
    #[error("durable event admission failed")]
    EventAdmissionFailed,
    /// The approval service could not process an approval request.
    #[error("approval service unavailable")]
    ApprovalUnavailable,
    /// The adapter encountered a failure without a safe public classification.
    #[error("governance service failed")]
    Internal,
}

impl GovernanceError {
    /// Returns the stable machine-readable error code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationUnavailable => "AUTHORIZATION_UNAVAILABLE",
            Self::PolicyUnavailable => "POLICY_UNAVAILABLE",
            Self::EventAdmissionFailed => "EVENT_ADMISSION_FAILED",
            Self::ApprovalUnavailable => "APPROVAL_UNAVAILABLE",
            Self::Internal => "INTERNAL_FAILURE",
        }
    }

    /// Returns whether retrying may succeed without changing the request.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::AuthorizationUnavailable
                | Self::PolicyUnavailable
                | Self::EventAdmissionFailed
                | Self::ApprovalUnavailable
        )
    }
}
