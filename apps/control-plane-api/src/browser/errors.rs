//! A closed error vocabulary: no provider, database or tonic details cross the
//! browser boundary, even when an upstream error contains credentials.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserError {
    InvalidRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    RateLimited,
    Unavailable,
    CapabilityUnavailable,
    Internal,
}

impl BrowserError {
    pub(crate) fn from_credential_error(error: &crate::CommandError) -> Self {
        match error.code {
            crate::CommandErrorCode::CredentialVerifierUnavailable
            | crate::CommandErrorCode::Internal => Self::Unavailable,
            _ => Self::Unauthenticated,
        }
    }

    pub fn from_status(status: &tonic::Status) -> Self {
        use tonic::Code;
        match status.code() {
            Code::InvalidArgument | Code::OutOfRange => Self::InvalidRequest,
            Code::Unauthenticated => Self::Unauthenticated,
            Code::PermissionDenied => Self::Forbidden,
            Code::NotFound => Self::NotFound,
            Code::AlreadyExists | Code::Aborted | Code::FailedPrecondition => Self::Conflict,
            Code::ResourceExhausted => Self::RateLimited,
            Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled => Self::Unavailable,
            Code::Unimplemented => Self::CapabilityUnavailable,
            Code::Ok | Code::Unknown | Code::Internal | Code::DataLoss => Self::Internal,
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable | Self::CapabilityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for BrowserError {}

impl IntoResponse for BrowserError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status(),
            Json(serde_json::json!({
                "error": {"code": self.code()}
            })),
        )
            .into_response();
        secure_api_response(&mut response);
        response
    }
}

/// Apply to auth/API responses, including redirects and framework rejections.
/// The separately served console HTML owns its script/style CSP.
pub fn secure_api_response(response: &mut Response) {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests;
