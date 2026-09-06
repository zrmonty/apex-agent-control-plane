//! Standalone std-only harness for the exact production confined reader. Can
//! run with rustc --test in the existing Linux verification image, without
//! compiling concurrent shared contract changes or needing network services.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![forbid(unsafe_code)]

#[derive(Debug)]
struct EnrollmentError;
#[path = "../src/managed_evidence/protected.rs"]
mod protected;

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

fn fixture() -> Option<PathBuf> {
    let root = std::env::var_os("APEX_EVIDENCE_LINUX_TEST_BASE")?;
    let name = format!(
        "reader-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let base = PathBuf::from(root).join(name);
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    Some(base)
}
fn file(base: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = base.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn linux_protected_evidence_reads_private_file_and_atomic_replacement() {
    let Some(base) = fixture() else {
        eprintln!("SKIP: APEX_EVIDENCE_LINUX_TEST_BASE unset");
        return;
    };
    let path = file(&base, "enrollment.json", b"first");
    assert_eq!(protected::read(&path, &base).unwrap(), b"first");
    let next = file(&base, "next.json", b"second");
    fs::rename(next, &path).unwrap();
    assert_eq!(protected::read(&path, &base).unwrap(), b"second");
}

#[test]
fn linux_protected_evidence_refuses_modes_links_ancestors_and_size() {
    let Some(base) = fixture() else {
        eprintln!("SKIP: APEX_EVIDENCE_LINUX_TEST_BASE unset");
        return;
    };
    let path = file(&base, "enrollment.json", b"profile");
    for mode in [0o640, 0o644, 0o660, 0o700] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(protected::read(&path, &base).is_err(), "mode {mode:o}");
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = base.join("link.json");
    symlink(&path, &alias).unwrap();
    assert!(protected::read(&alias, &base).is_err());
    let ancestor = base.join("alias");
    symlink(&base, &ancestor).unwrap();
    assert!(protected::read(&ancestor.join("enrollment.json"), &base).is_err());
    assert!(protected::read(&ancestor.join("enrollment.json"), &ancestor).is_err());
    assert!(protected::read(&path, &base.join("not-parent")).is_err());
    assert!(protected::read(&base.join("../enrollment.json"), &base).is_err());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(protected::read(&path, &base).is_err());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let hard = base.join("hard.json");
    fs::hard_link(&path, &hard).unwrap();
    assert!(protected::read(&path, &base).is_err());
    let big = file(&base, "large.json", &vec![b'a'; 262_145]);
    assert!(protected::read(&big, &base).is_err());
    assert!(protected::read(&file(&base, "empty.json", b""), &base).is_err());
    assert!(protected::read(&base, &base).is_err());
    let fifo = base.join("pipe");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let started = std::time::Instant::now();
    assert!(protected::read(&fifo, &base).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}
