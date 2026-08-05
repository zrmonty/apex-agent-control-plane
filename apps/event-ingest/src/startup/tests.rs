use super::auth::{
    FileBearerResolver, constant_time_token_eq, default_bearer_subject,
    parse_bearer_peer_certificate_sha256, validate_bearer_subject,
};
use super::env::{attempts_value, optional_path_value, required, valid_identifier, valid_scope};
use super::error::startup_gateway_error;
use super::secrets::{read_bounded, read_token, trusted_secret_path};
use apex_event_ingest::{BearerTokenResolver, GatewayError, PeerIdentity};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

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
    assert!(attempts_value(Some("9")).is_err());
    assert!(attempts_value(Some("not-a-number")).is_err());
    assert!(attempts_value(Some("-1")).is_err());
}

#[test]
fn scope_and_identifier_validators_cover_length_and_character_boundaries() {
    assert!(valid_scope(&format!("{}/{}", "a".repeat(256), "b".repeat(256))));
    assert!(!valid_scope(&format!("{}/{}", "a".repeat(257), "b")));
    assert!(valid_scope("workspace.one_two:three-four/namespace"));
    assert!(!valid_scope("workspace/namespace/extra"));
    assert!(!valid_scope("workspace/"));
    assert!(!valid_scope("/namespace"));
    assert!(!valid_scope("work space/namespace"));
    assert!(!valid_scope("работа/namespace"));

    assert!(valid_identifier("agent.one_two:three-four"));
    assert!(valid_identifier(&"a".repeat(256)));
    assert!(!valid_identifier(&"a".repeat(257)));
    assert!(!valid_identifier(""));
    assert!(!valid_identifier("../etc/passwd"));
    assert!(!valid_identifier("agent id"));
    assert!(!valid_identifier("агент"));
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

    // Whatever this platform's default permissions/ACL happen to be, the
    // private-key branch must agree exactly with the underlying permissions
    // primitive -- not silently ignore it either way.
    fs::write(&file, b"private-key-material").unwrap();
    let canonical = file.canonicalize().unwrap();
    let restricted = apex_event_ingest::permissions::private_key_permissions_restricted(&canonical);
    assert_eq!(
        trusted_secret_path(&file, &root, 4096, true, "secret").is_ok(),
        restricted
    );
    assert!(trusted_secret_path(&file, &root, 4096, false, "secret").is_ok());

    // A missing base directory cannot be canonicalized.
    assert!(trusted_secret_path(&file, &root.join("does-not-exist"), 32, false, "secret").is_err());
}

fn file_bearer_fixture(token: &str) -> (FileBearerResolver, tempfile_like::TempTokenDir) {
    let dir = tempfile_like::TempTokenDir::new("apex-file-bearer");
    let token_path = dir.root.join("token");
    fs::write(&token_path, token).unwrap();
    let mut scopes = HashSet::new();
    scopes.insert("acme/prod".to_owned());
    let resolver = FileBearerResolver::new(
        Zeroizing::new(token.to_owned()),
        token_path,
        dir.root.clone(),
        "spiffe://apex/test".to_owned(),
        "reference-agent".to_owned(),
        Arc::new(scopes),
        [7u8; 32],
    );
    (resolver, dir)
}

mod tempfile_like {
    use std::fs;
    use std::path::PathBuf;

    /// Minimal self-cleaning temp directory (no extra dev-dependency needed).
    pub(super) struct TempTokenDir {
        pub(super) root: PathBuf,
    }

    impl TempTokenDir {
        pub(super) fn new(prefix: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "{prefix}-{}-{nanos}-{sequence}",
                std::process::id(),
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for TempTokenDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
fn file_bearer_resolver_requires_a_peer_and_rejects_certificate_mismatch() {
    let (resolver, _dir) = file_bearer_fixture("correct-token");
    assert!(resolver.resolve("correct-token").is_err());
    let wrong_peer = PeerIdentity {
        certificate_sha256: [9u8; 32],
    };
    assert!(
        resolver
            .resolve_with_peer("correct-token", Some(&wrong_peer))
            .is_err()
    );
}

#[test]
fn file_bearer_resolver_accepts_the_bound_peer_and_matching_token_only() {
    let (resolver, _dir) = file_bearer_fixture("correct-token");
    let peer = PeerIdentity {
        certificate_sha256: [7u8; 32],
    };
    assert!(
        resolver
            .resolve_with_peer("wrong-token", Some(&peer))
            .is_err()
    );
    let caller = resolver
        .resolve_with_peer("correct-token", Some(&peer))
        .expect("matching token and peer must authenticate");
    assert!(caller.is_authenticated());
}
