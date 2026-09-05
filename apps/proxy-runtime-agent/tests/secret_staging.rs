//! Public staging boundary: filesystem effects only, never launch authorization.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
#[path = "secret_staging/confinement.rs"]
mod confinement;
#[cfg(target_os = "linux")]
#[path = "secret_staging/positive.rs"]
mod positive;
#[cfg(target_os = "linux")]
#[path = "secret_staging/support.rs"]
mod support;
#[cfg(target_os = "linux")]
#[path = "secret_staging/validation.rs"]
mod validation;

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_does_not_create_roots_or_modify_existing_files() {
    use apex_proxy_runtime_agent::secrets::{StagingError, StagingOwner};
    use std::{fs, path::Path};

    let parent = std::env::temp_dir();
    let name = format!("apex-staging-test-{}", uuid::Uuid::now_v7());
    let root = parent.join(&name);
    assert_eq!(root.parent(), Some(parent.as_path()));
    fs::create_dir(&root).expect("create exclusively owned test root");
    let sentinel = root.join("sentinel");
    fs::write(&sentinel, b"existing-content").unwrap();
    let state = root.join("absent-state");
    let source = root.join("absent-source");
    let result = StagingOwner::open(&state, &source);
    assert!(matches!(result, Err(StagingError::Unsupported)));
    assert!(matches!(
        StagingOwner::open(Path::new("relative"), &root),
        Err(StagingError::Unsupported)
    ));
    assert!(!state.exists());
    assert!(!source.exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"existing-content");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    // Exact files only; no recursive cleanup of an externally supplied path.
    assert_eq!(root.file_name().unwrap(), name.as_str());
    assert!(
        !fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(sentinel).unwrap();
    fs::remove_dir(root).unwrap();
}
