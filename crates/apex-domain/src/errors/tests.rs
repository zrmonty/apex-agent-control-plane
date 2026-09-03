use super::code::GatewayErrorCode;
use super::diagnostics::GatewayDiagnosticReport;
use super::gateway::GatewayError;

#[test]
fn every_error_code_has_a_stable_string_and_catalog_entry() {
    let codes = [
        GatewayErrorCode::Unauthenticated,
        GatewayErrorCode::InvalidAuthorization,
        GatewayErrorCode::ScopeDenied,
        GatewayErrorCode::InvalidEventId,
        GatewayErrorCode::InvalidEnvelope,
        GatewayErrorCode::InvalidStructure,
        GatewayErrorCode::SecretExposure,
        GatewayErrorCode::InvalidTimestamp,
        GatewayErrorCode::InvalidIntegrity,
        GatewayErrorCode::PayloadTooLarge,
        GatewayErrorCode::IdempotencyCapacity,
        GatewayErrorCode::IdempotencyInProgress,
        GatewayErrorCode::RateLimited,
        GatewayErrorCode::AdmissionBusy,
        GatewayErrorCode::PublishFailed,
        GatewayErrorCode::Internal,
        GatewayErrorCode::SubjectTooLong,
        GatewayErrorCode::InvalidRetryConfiguration,
        GatewayErrorCode::InvalidNatsConfiguration,
        GatewayErrorCode::InvalidNatsPublishRequest,
        GatewayErrorCode::NatsConnectionFailed,
        GatewayErrorCode::IdempotencyConflict,
        GatewayErrorCode::InvalidSinkConfiguration,
        GatewayErrorCode::InvalidOutboxConfiguration,
        GatewayErrorCode::InvalidIdempotencyConfiguration,
    ];
    for code in codes {
        let error = GatewayError::new(code);
        assert!(!code.as_str().is_empty());
        assert_eq!(error.code, code);
        assert!(!error.summary.is_empty());
        assert!(!error.cause.is_empty());
        assert!(!error.recommended_next_steps.is_empty());
        let status = error.grpc_status();
        assert!(!status.is_empty());
        let _ = error.grpc_status_value();
        let report: GatewayDiagnosticReport =
            error.diagnostic_report("event-ingest.coverage", "workspace", "namespace", None);
        assert!(!report.to_ai_markdown().is_empty());
    }
}

#[test]
fn auth_failures_use_a_generic_grpc_message() {
    let message = GatewayError::unauthenticated()
        .grpc_status_value()
        .message()
        .to_owned();
    assert!(!message.contains("Bearer"));
    assert_eq!(
        GatewayError::invalid_authorization().grpc_status(),
        "UNAUTHENTICATED"
    );
    assert_eq!(
        GatewayErrorCode::InvalidAuthorization.public_code(),
        "UNAUTHENTICATED"
    );
    assert_eq!(
        GatewayErrorCode::RateLimited.public_code(),
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        GatewayErrorCode::AdmissionBusy.public_code(),
        "RESOURCE_EXHAUSTED"
    );
    let rate_limit_message = GatewayError::new(GatewayErrorCode::RateLimited)
        .grpc_status_value()
        .message()
        .to_owned();
    assert_eq!(
        rate_limit_message,
        "Request capacity is temporarily unavailable. Retry with exponential backoff."
    );
}


