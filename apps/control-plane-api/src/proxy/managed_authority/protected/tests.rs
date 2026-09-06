use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

#[test]
#[ignore = "requires the explicitly private Linux fixture; run with --ignored"]
fn actual_linux_private_document_rejects_links_permissions_fifo_and_size() {
    // This test requires an explicit root-owned private Linux fixture directory;
    // absence is not counted as a successful protection check.
    let base =
        std::env::var_os("APEX_MANAGED_POLICY_TEST_BASE").expect("private Linux fixture required");
    let base = std::path::PathBuf::from(base).join(uuid::Uuid::now_v7().to_string());
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let path = base.join("profile.json");
    fs::write(&path, b"private-digest-document").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read(&path, &base).unwrap(), b"private-digest-document");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read(&path, &base).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = base.join("symlink");
    symlink(&path, &alias).unwrap();
    assert!(read(&alias, &base).is_err());
    let hardlink = base.join("hardlink");
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(read(&path, &base).is_err());
    fs::remove_file(&hardlink).unwrap();
    let fifo = base.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert!(read(&fifo, &base).is_err());
    fs::write(&path, vec![b'x'; 262145]).unwrap();
    assert!(read(&path, &base).is_err());
    fs::write(&path, b"bounded").unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o722)).unwrap();
    assert!(read(&path, &base).is_err());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(read(&path, Path::new("/")).is_err());
    // Only exact files just created here are removed, never a directory subtree.
    for owned in [&alias, &fifo, &path] {
        fs::remove_file(owned).unwrap();
    }
    fs::remove_dir(base).unwrap();
}
