use super::auth::{
    constant_time_token_eq, default_bearer_subject, parse_bearer_peer_certificate_sha256,
    validate_bearer_subject,
};
use super::env::{attempts_value, optional_path_value, required, valid_scope};
use super::error::startup_gateway_error;
use super::secrets::{read_bounded, read_token, trusted_secret_path};
use apex_event_ingest::GatewayError;
use std::fs;
use std::path::Path;

#[test]
fn token_comparison_handles_length_boundaries_without_aliasing() {
    assert!(!constant_time_token_eq("", ""));
    assert!(constant_time_token_eq("a", "a"));
    assert!(!constant_time_token_eq("a", "a\0"));
    assert!(!constant_time_token_eq(&"a".repeat(256), &"a".repeat(512)));
    assert!(!constant_time_token_eq(&"a".repeat(4096), "a"));
}

#[test]
fn startup_errors_preserve_the_project_diagnostic_fields() {
    let error = startup_gateway_error(GatewayError::invalid_retry_configuration());
    let message = error.to_string();
    assert!(message.contains("INVALID_RETRY_CONFIGURATION"));
    assert!(message.contains("Cause:"));
    assert!(message.contains("Next:"));
}

#[test]
fn scope_and_retry_configuration_reject_ambiguous_values() {
    assert!(valid_scope("workspace/namespace"));
    assert!(!valid_scope("workspace"));
    assert!(!valid_scope("workspace/"));
    assert!(!valid_scope("../namespace"));
    assert_eq!(attempts_value(None).unwrap(), 3);
    assert_eq!(attempts_value(Some("8")).unwrap(), 8);
    assert!(attempts_value(Some("0")).is_err());
    assert!(attempts_value(Some("not-a-number")).is_err());
}

#[test]
fn bearer_subject_is_bounded_and_control_free() {
    assert_eq!(
        default_bearer_subject("reference-agent"),
        "spiffe://apex/workload/reference-agent"
    );
    assert!(validate_bearer_subject("spiffe://apex/workload/agent-1").is_ok());
    assert!(validate_bearer_subject("agent-1").is_ok());
    assert!(validate_bearer_subject("").is_err());
    assert!(validate_bearer_subject(&"a".repeat(257)).is_err());
    assert!(validate_bearer_subject("agent\n1").is_err());
    assert!(validate_bearer_subject("agent/1").is_err());
    assert!(validate_bearer_subject("агент").is_err());
}

#[test]
fn bearer_certificate_binding_requires_and_decodes_a_sha256_fingerprint() {
    assert!(parse_bearer_peer_certificate_sha256("").is_err());
    assert_eq!(
        parse_bearer_peer_certificate_sha256(&"00".repeat(32)).unwrap(),
        [0u8; 32]
    );
    assert!(parse_bearer_peer_certificate_sha256(&"gg".repeat(32)).is_err());
}

#[test]
fn bounded_file_and_environment_helpers_enforce_limits() {
    assert_eq!(
        optional_path_value(Some("relative/path")),
        Some(Path::new("relative/path").to_path_buf())
    );
    assert!(optional_path_value(Some("")).is_none());
    assert!(optional_path_value(None).is_none());

    let root = std::env::temp_dir().join(format!("apex-main-{}", std::process::id()));
    let _ = fs::create_dir_all(&root);
    let file = root.join("secret");
    fs::write(&file, b"token\n").unwrap();
    assert_eq!(read_bounded(&file, 32, "secret").unwrap(), b"token\n");
    assert_eq!(read_token(&file, "token").unwrap(), "token");
    fs::write(&file, b"bad token").unwrap();
    assert!(read_token(&file, "token").is_err());
    assert!(trusted_secret_path(&file, &root, 32, false, "secret").is_ok());
    fs::write(&file, vec![0; 33]).unwrap();
    assert!(read_bounded(&file, 32, "secret").is_err());
    assert!(read_bounded(&root.join("missing"), 32, "secret").is_err());
    assert!(trusted_secret_path(&file, &root.join("outside"), 32, false, "secret").is_err());
    assert!(required("APEX_TEST_MISSING").is_err());
}
