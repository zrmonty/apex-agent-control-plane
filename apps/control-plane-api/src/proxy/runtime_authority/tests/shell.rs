use std::path::PathBuf;

use super::super::{RuntimeAuthorityError, RuntimeAuthorityOwner, RuntimeAuthorityPolicyFiles};

fn base() -> PathBuf {
    // An absolute, intentionally uncreated path proves constructors do no file I/O.
    std::env::temp_dir().join(format!("apex-authority-uncreated-{}", uuid::Uuid::now_v7()))
}

#[test]
fn fixed_path_constructor_accepts_explicit_paths_without_io_and_owner_retains_settings() {
    let base = base();
    assert!(!base.exists());
    let files =
        RuntimeAuthorityPolicyFiles::new(base, "peer.json".into(), "enrollment.json".into())
            .expect("explicit bounded settings are not a load");
    let owner =
        RuntimeAuthorityOwner::new(files, "postgresql://component.invalid/PRIVATE-DSN-CANARY")
            .expect("owner construction must not connect or require an existing directory");
    assert!(!format!("{owner:?}").contains("PRIVATE-DSN-CANARY"));
    // Drop has no started workers here. This is not worker shutdown evidence.
    drop(owner);
}

#[test]
fn empty_or_relative_trusted_base_and_missing_file_settings_refuse() {
    for (trusted, peer, enrollment) in [
        (PathBuf::new(), "peer.json".into(), "enrollment.json".into()),
        (
            PathBuf::from("relative"),
            "peer.json".into(),
            "enrollment.json".into(),
        ),
        (base(), PathBuf::new(), "enrollment.json".into()),
        (base(), "peer.json".into(), PathBuf::new()),
    ] {
        assert!(matches!(
            RuntimeAuthorityPolicyFiles::new(trusted, peer, enrollment),
            Err(RuntimeAuthorityError::Unavailable)
        ));
    }
}

#[test]
fn empty_database_setting_refuses_instead_of_inventing_a_connection() {
    let files =
        RuntimeAuthorityPolicyFiles::new(base(), "peer.json".into(), "enrollment.json".into())
            .unwrap();
    assert!(matches!(
        RuntimeAuthorityOwner::new(files, ""),
        Err(RuntimeAuthorityError::Unavailable)
    ));
}

#[tokio::test]
async fn owner_construction_refuses_entered_tokio_even_with_explicit_settings() {
    let files =
        RuntimeAuthorityPolicyFiles::new(base(), "peer.json".into(), "enrollment.json".into())
            .unwrap();
    assert!(matches!(
        RuntimeAuthorityOwner::new(files, "postgresql://component.invalid/unit"),
        Err(RuntimeAuthorityError::Unavailable)
    ));
}

#[test]
fn error_codes_statuses_and_diagnostics_are_fixed_and_have_no_source_chain() {
    use RuntimeAuthorityError::*;
    for (error, code, text) in [
        (
            Unavailable,
            tonic::Code::Unavailable,
            "RUNTIME_AUTHORITY_UNAVAILABLE",
        ),
        (
            InvalidRequest,
            tonic::Code::InvalidArgument,
            "RUNTIME_AUTHORITY_INVALID_REQUEST",
        ),
        (
            EnrollmentDenied,
            tonic::Code::PermissionDenied,
            "RUNTIME_AUTHORITY_ENROLLMENT_DENIED",
        ),
        (
            PolicyChanged,
            tonic::Code::FailedPrecondition,
            "RUNTIME_AUTHORITY_POLICY_CHANGED",
        ),
        (
            Busy,
            tonic::Code::ResourceExhausted,
            "RUNTIME_AUTHORITY_BUSY",
        ),
        (
            Deadline,
            tonic::Code::DeadlineExceeded,
            "RUNTIME_AUTHORITY_DEADLINE",
        ),
        (
            Cancelled,
            tonic::Code::Cancelled,
            "RUNTIME_AUTHORITY_CANCELLED",
        ),
    ] {
        let status = error.status();
        assert_eq!(status.code(), code);
        assert_eq!(status.message(), text);
        assert_eq!(error.code(), text);
        assert_eq!(format!("{error:?}"), text);
        assert_eq!(error.to_string(), text);
        assert!(std::error::Error::source(&error).is_none());
        assert!(status.details().is_empty());
    }
}
