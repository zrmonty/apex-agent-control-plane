use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingErrorCode {
    InvalidField,
    Capacity,
    DuplicateId,
    FingerprintConflict,
    NotFound,
    ScopeDenied,
    InvalidTransition,
    EntropyUnavailable,
    ClockUnavailable,
}

impl FindingErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidField => "INVALID_SECURITY_FINDING_FIELD",
            Self::Capacity => "SECURITY_FINDING_CAPACITY",
            Self::DuplicateId => "SECURITY_FINDING_ID_CONFLICT",
            Self::FingerprintConflict => "SECURITY_FINDING_FINGERPRINT_CONFLICT",
            Self::NotFound => "SECURITY_FINDING_NOT_FOUND",
            Self::ScopeDenied => "SECURITY_FINDING_SCOPE_DENIED",
            Self::InvalidTransition => "SECURITY_FINDING_INVALID_TRANSITION",
            Self::EntropyUnavailable => "SECURITY_FINDING_ENTROPY_UNAVAILABLE",
            Self::ClockUnavailable => "SECURITY_FINDING_CLOCK_UNAVAILABLE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingError {
    pub code: FindingErrorCode,
    pub summary: &'static str,
    pub cause: &'static str,
    pub retryable: bool,
    pub next_steps: &'static [&'static str],
}

impl FindingError {
    pub fn invalid_field() -> Self {
        Self {
            code: FindingErrorCode::InvalidField,
            summary: "The security finding contains an invalid field.",
            cause: "A scope, UUID, hash, detector, evidence path, or bounded collection failed the finding contract.",
            retryable: false,
            next_steps: &[
                "Validate identifiers and SHA-256 evidence hashes before creating the finding.",
            ],
        }
    }

    pub(crate) fn capacity() -> Self {
        Self {
            code: FindingErrorCode::Capacity,
            summary: "The security finding or status-history quota is exhausted for this scope or the global hard cap.",
            cause: "The append-only boundary refuses new records or status updates rather than evicting security evidence; another tenant cannot consume this scope's quota.",
            retryable: true,
            next_steps: &[
                "Archive findings through the approved retention workflow or increase the affected scope quota/global hard cap.",
            ],
        }
    }

    pub(crate) fn duplicate_id() -> Self {
        Self {
            code: FindingErrorCode::DuplicateId,
            summary: "The finding ID is already bound to different evidence.",
            cause: "Immutable finding IDs cannot be reused for a changed record.",
            retryable: false,
            next_steps: &[
                "Use the original record for replay or generate a new UUIDv7 finding ID.",
            ],
        }
    }

    pub(crate) fn fingerprint_conflict() -> Self {
        Self {
            code: FindingErrorCode::FingerprintConflict,
            summary: "The finding fingerprint is already bound to different evidence or policy.",
            cause: "A deterministic security signal cannot be silently downgraded or replaced by a changed record.",
            retryable: false,
            next_steps: &[
                "Replay the original finding or create a new detector fingerprint for a materially different signal.",
            ],
        }
    }

    pub(crate) fn not_found() -> Self {
        Self {
            code: FindingErrorCode::NotFound,
            summary: "The requested security finding was not found.",
            cause: "The supplied finding ID is not present in this scoped store.",
            retryable: false,
            next_steps: &["Verify the finding ID and authenticated scope before retrying."],
        }
    }

    pub(crate) fn scope_denied() -> Self {
        Self {
            code: FindingErrorCode::ScopeDenied,
            summary: "The security finding is outside the caller's scope.",
            cause: "Finding reads and status changes require an exact workspace/namespace scope match.",
            retryable: false,
            next_steps: &[
                "Use an authorized scope or request the required security.finding permission.",
            ],
        }
    }

    pub(crate) fn invalid_transition() -> Self {
        Self {
            code: FindingErrorCode::InvalidTransition,
            summary: "The security finding status transition is not allowed.",
            cause: "Terminal findings cannot be reopened and containment actions are allowlisted and reversible.",
            retryable: false,
            next_steps: &[
                "Read the current status and submit an allowed transition with an authorized actor scope.",
            ],
        }
    }

    pub(crate) fn entropy_unavailable() -> Self {
        Self {
            code: FindingErrorCode::EntropyUnavailable,
            summary: "The security finding ID could not be generated securely.",
            cause: "The operating-system cryptographic random source was unavailable; a predictable fallback is never used.",
            retryable: true,
            next_steps: &["Restore the host random source and retry finding creation."],
        }
    }

    pub(crate) fn clock_unavailable() -> Self {
        Self {
            code: FindingErrorCode::ClockUnavailable,
            summary: "The security finding timestamp could not be established.",
            cause: "The system clock is earlier than the Unix epoch; epoch-zero timestamps are not accepted as security evidence.",
            retryable: true,
            next_steps: &[
                "Restore a valid system clock and retry finding creation or status changes.",
            ],
        }
    }
}

impl fmt::Display for FindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let next = self
            .next_steps
            .first()
            .copied()
            .unwrap_or("No remediation guidance is available.");
        write!(
            f,
            "{}: {} Cause: {} Next: {}",
            self.code.as_str(),
            self.summary,
            self.cause,
            next
        )
    }
}

impl std::error::Error for FindingError {}


