use std::fmt;

/// Fixed safe callback refusals; no raw parser, path, transport or SQL source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAuthorityError {
    /// Invalid, stale, unavailable or stopped owned dependency.
    Unavailable,
    /// Unsupported or malformed generated request or timeout metadata.
    InvalidRequest,
    /// No exact current deployment enrollment and controller-worker binding.
    EnrollmentDenied,
    /// The selected immutable policy generation was replaced or disabled.
    PolicyChanged,
    /// The fixed bounded queue cannot admit another job.
    Busy,
    /// The one local request budget is exhausted.
    Deadline,
    /// The caller or owner cancelled the request.
    Cancelled,
}

impl RuntimeAuthorityError {
    /// Safe static diagnostic; never contains deployment or request data.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "RUNTIME_AUTHORITY_UNAVAILABLE",
            Self::InvalidRequest => "RUNTIME_AUTHORITY_INVALID_REQUEST",
            Self::EnrollmentDenied => "RUNTIME_AUTHORITY_ENROLLMENT_DENIED",
            Self::PolicyChanged => "RUNTIME_AUTHORITY_POLICY_CHANGED",
            Self::Busy => "RUNTIME_AUTHORITY_BUSY",
            Self::Deadline => "RUNTIME_AUTHORITY_DEADLINE",
            Self::Cancelled => "RUNTIME_AUTHORITY_CANCELLED",
        }
    }

    pub(super) fn status(self) -> tonic::Status {
        let code = match self {
            Self::Unavailable => tonic::Code::Unavailable,
            Self::InvalidRequest => tonic::Code::InvalidArgument,
            Self::EnrollmentDenied => tonic::Code::PermissionDenied,
            Self::PolicyChanged => tonic::Code::FailedPrecondition,
            Self::Busy => tonic::Code::ResourceExhausted,
            Self::Deadline => tonic::Code::DeadlineExceeded,
            Self::Cancelled => tonic::Code::Cancelled,
        };
        tonic::Status::new(code, self.code())
    }
}

impl fmt::Display for RuntimeAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for RuntimeAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for RuntimeAuthorityError {}
