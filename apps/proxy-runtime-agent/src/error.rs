//! Static errors: no input, JSON, engine output or parser source chain.

/// Bounded pure-boundary refusal categories, never engine diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeError {
    /// The target's identifiers or integer relation inputs are invalid.
    InvalidTarget,
    /// Configuration metadata is invalid or does not match the target.
    InvalidConfigurationBinding,
    /// The supported bounded inspect document cannot be decoded safely.
    InvalidInspect,
    /// The externally supplied expectation has malformed fields.
    InvalidExpectedOwnership,
    /// Inspect identity differs from the externally supplied expectation.
    OwnershipMismatch,
    /// Docker state is outside the supported closed state vocabulary.
    UnsupportedState,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidTarget => "RUNTIME_INVALID_TARGET",
            Self::InvalidConfigurationBinding => "RUNTIME_INVALID_CONFIGURATION_BINDING",
            Self::InvalidInspect => "RUNTIME_INVALID_INSPECT",
            Self::InvalidExpectedOwnership => "RUNTIME_INVALID_EXPECTED_OWNERSHIP",
            Self::OwnershipMismatch => "RUNTIME_OWNERSHIP_MISMATCH",
            Self::UnsupportedState => "RUNTIME_UNSUPPORTED_STATE",
        })
    }
}

impl std::error::Error for RuntimeError {}
