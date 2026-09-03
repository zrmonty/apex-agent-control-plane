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
