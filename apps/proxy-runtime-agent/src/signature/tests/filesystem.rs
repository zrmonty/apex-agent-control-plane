use super::*;
use rustix::fs::{Gid, Uid, chown};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};

struct Fixture {
    root: PathBuf,
    inode: u64,
    exe: PathBuf,
    cache: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "explicit disposable root acceptance"
        );
        let root = Path::new("/").join(format!("apex-signature-test-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        let exe = root.join("cosign");
        fs::copy("/usr/local/bin/apex-test-cosign", &exe).unwrap();
        mode(&exe, 0o755);
        let cache = root.join("cache");
        fs::create_dir(&cache).unwrap();
        mode(&cache, 0o700);
        let inode = fs::symlink_metadata(&root).unwrap().ino();
        Self {
            root,
            inode,
            exe,
            cache,
        }
    }
    fn open(&self) -> Result<SignatureVerifier, SignatureError> {
        SignatureVerifier::open(&self.exe, &self.cache)
    }
    fn denied(&self) {
        assert!(matches!(
            self.open(),
            Err(SignatureError::InvalidConfiguration)
        ));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(self.root.parent(), Some(Path::new("/")));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("apex-signature-test-")
        );
        let info = fs::symlink_metadata(&self.root).unwrap();
        assert!(info.is_dir() && !info.file_type().is_symlink() && info.ino() == self.inode);
        // Only this UUID/inode-checked synthetic fixture tree is removed.
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

#[test]
#[ignore = "explicit disposable-root filesystem acceptance"]
fn protected_paths_and_cache_identity_are_checked() {
    let fixture = Fixture::new();
    fixture.open().unwrap();
    for path in [&fixture.root, &fixture.exe, &fixture.cache] {
        let original = fs::metadata(path).unwrap().mode() & 0o7777;
        mode(path, original | 0o022);
        fixture.denied();
        mode(path, original);
        chown(path, Some(Uid::from_raw(12345)), None).unwrap();
        fixture.denied();
        chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
    }
    for path in [&fixture.exe, &fixture.cache] {
        let held = path.with_extension("held");
        fs::rename(path, &held).unwrap();
        symlink(&held, path).unwrap();
        fixture.denied();
        fs::remove_file(path).unwrap();
        fs::rename(&held, path).unwrap();
    }
    let link = fixture.root.with_extension("link");
    symlink(&fixture.root, &link).unwrap();
    assert!(SignatureVerifier::open(&link.join("cosign"), &fixture.cache).is_err());
    assert!(SignatureVerifier::open(&fixture.exe, &link.join("cache")).is_err());
    fs::remove_file(link).unwrap();
    let verifier = fixture.open().unwrap();
    fs::rename(&fixture.cache, fixture.root.join("old-cache")).unwrap();
    fs::create_dir(&fixture.cache).unwrap();
    mode(&fixture.cache, 0o700);
    assert_eq!(
        verifier
            .verify(
                &catalog("keyless@projectsigstore.iam.gserviceaccount.com"),
                "cosign-fixture",
                IMAGE,
                Duration::from_secs(30),
                &AtomicBool::new(false)
            )
            .unwrap_err(),
        SignatureError::InvalidConfiguration
    );
}

#[test]
#[ignore = "explicit real-Cosign held-executable acceptance"]
fn held_executable_survives_path_replacement_and_busy_slot_refuses() {
    let fixture = Fixture::new();
    let verifier = fixture.open().unwrap();
    fs::rename(&fixture.exe, fixture.root.join("held-cosign")).unwrap();
    fs::copy("/usr/bin/false", &fixture.exe).unwrap();
    mode(&fixture.exe, 0o755);
    let catalog = catalog("keyless@projectsigstore.iam.gserviceaccount.com");
    let cancel = AtomicBool::new(false);
    assert_eq!(
        verifier
            .verify(
                &catalog,
                "cosign-fixture",
                IMAGE,
                Duration::from_secs(30),
                &cancel
            )
            .unwrap()
            .image_ref(),
        IMAGE
    );
    let _held = verifier.inner.slot.lock().unwrap();
    assert_eq!(
        verifier
            .verify(
                &catalog,
                "cosign-fixture",
                IMAGE,
                Duration::from_secs(30),
                &cancel
            )
            .unwrap_err(),
        SignatureError::Overloaded
    );
}
