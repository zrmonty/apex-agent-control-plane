use super::*;
use axum::{
    body::{Body, to_bytes},
    http::header,
};
use tonic::Code;

#[test]
fn upstream_codes_have_closed_public_meanings() {
    for (code, expected, status) in [
        (Code::InvalidArgument, BrowserError::InvalidRequest, 400),
        (Code::OutOfRange, BrowserError::InvalidRequest, 400),
        (Code::Unauthenticated, BrowserError::Unauthenticated, 401),
        (Code::PermissionDenied, BrowserError::Forbidden, 403),
        (Code::NotFound, BrowserError::NotFound, 404),
        (Code::AlreadyExists, BrowserError::Conflict, 409),
        (Code::Aborted, BrowserError::Conflict, 409),
        (Code::FailedPrecondition, BrowserError::Conflict, 409),
        (Code::ResourceExhausted, BrowserError::RateLimited, 429),
        (Code::Unavailable, BrowserError::Unavailable, 503),
        (Code::DeadlineExceeded, BrowserError::Unavailable, 503),
        (Code::Cancelled, BrowserError::Unavailable, 503),
        (
            Code::Unimplemented,
            BrowserError::CapabilityUnavailable,
            503,
        ),
        (Code::Internal, BrowserError::Internal, 500),
        (Code::Unknown, BrowserError::Internal, 500),
        (Code::DataLoss, BrowserError::Internal, 500),
        (Code::Ok, BrowserError::Internal, 500),
    ] {
        let mapped = BrowserError::from_status(&tonic::Status::new(code, "secret-marker"));
        assert_eq!(mapped, expected, "{code:?}");
        assert_eq!(mapped.status().as_u16(), status);
    }
}

#[tokio::test]
async fn every_error_is_bounded_safe_json_and_not_cacheable() {
    for (error, status, code) in [
        (BrowserError::InvalidRequest, 400, "invalid_request"),
        (BrowserError::Unauthenticated, 401, "unauthenticated"),
        (BrowserError::Forbidden, 403, "forbidden"),
        (BrowserError::NotFound, 404, "not_found"),
        (BrowserError::MethodNotAllowed, 405, "method_not_allowed"),
        (BrowserError::Conflict, 409, "conflict"),
        (BrowserError::PayloadTooLarge, 413, "payload_too_large"),
        (
            BrowserError::UnsupportedMediaType,
            415,
            "unsupported_media_type",
        ),
        (BrowserError::RateLimited, 429, "rate_limited"),
        (BrowserError::Unavailable, 503, "unavailable"),
        (
            BrowserError::CapabilityUnavailable,
            503,
            "capability_unavailable",
        ),
        (BrowserError::Internal, 500, "internal"),
    ] {
        let response = error.into_response();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_security_headers(&response);
        let bytes = to_bytes(response.into_body(), 128).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, serde_json::json!({"error": {"code": code}}));
        assert_eq!(error.to_string(), code);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[tokio::test]
async fn messages_details_and_metadata_never_leak_from_tonic() {
    let mut upstream = tonic::Status::with_details(
        Code::PermissionDenied,
        "Bearer access-secret-marker",
        b"refresh-secret-marker".as_slice().into(),
    );
    upstream
        .metadata_mut()
        .insert("authorization", "provider-secret-marker".parse().unwrap());
    let error = BrowserError::from_status(&upstream);
    let response = error.into_response();
    let headers = format!("{:?}", response.headers());
    let bytes = to_bytes(response.into_body(), 128).await.unwrap();
    let displayed = format!(
        "{error} {error:?} {headers} {}",
        String::from_utf8(bytes.to_vec()).unwrap()
    );
    assert!(!displayed.contains("secret-marker"));
    assert!(!displayed.contains("authorization"));
}

#[test]
fn secure_headers_replace_unsafe_values_without_destroying_cookies_or_redirects() {
    let mut response = Response::new(Body::empty());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "public, max-age=600".parse().unwrap(),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src *".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert(header::SET_COOKIE, "cookie-value".parse().unwrap());
    response
        .headers_mut()
        .insert(header::LOCATION, "/".parse().unwrap());
    secure_api_response(&mut response);
    assert_security_headers(&response);
    assert_eq!(response.headers()[header::SET_COOKIE], "cookie-value");
    assert_eq!(response.headers()[header::LOCATION], "/");
    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
    );
}

fn assert_security_headers(response: &Response) {
    let headers = response.headers();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    );
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
}
