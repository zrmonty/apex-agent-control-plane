use apex_proxy_runtime_agent::{
    proto::{RuntimeMaterialRole, RuntimeTarget},
    secrets::{ScopedMaterial, StagingError, StagingOwner},
};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const PROXY: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1001";
pub const OTHER: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1005";
pub const INSTANCE: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1004";
pub const HEALTH: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF8";
pub const CANARY: &[u8] = b"STAGING_PRIVATE_CANARY_7C";
// Deliberately not JSON: this primitive makes no claim of semantic validation.
pub const REVISION: &[u8] = b"synthetic revision bytes, not a published manifest";
pub const LAUNCH: &[u8] = b"synthetic launch bytes, not an authorized launch";

pub fn target() -> RuntimeTarget {
    RuntimeTarget {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        proxy_id: PROXY.into(),
        revision_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002".into(),
        generation: 9_007_199_254_740_993,
        fencing_token: 42,
    }
}

pub fn material(role: RuntimeMaterialRole, source_name: &str) -> ScopedMaterial {
    ScopedMaterial {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        proxy_id: PROXY.into(),
        reference: format!("secret://acme/prod/{PROXY}/{source_name}"),
        version: "v1".into(),
        role,
        source_name: source_name.into(),
    }
}

pub fn health() -> ScopedMaterial {
    material(RuntimeMaterialRole::HealthToken, "health-source")
}

pub fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

pub fn private_dir(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
    mode(path, 0o700);
}

/// Fixtures own UUID children of APEX_STAGING_TEST_ROOT, or `/` in main's
/// disposable root container. `/tmp` has an unsuitable writable ancestor.
pub struct Fixture {
    pub root: PathBuf,
    pub state: PathBuf,
    pub source: PathBuf,
    identity: (u64, u64),
    test_root: PathBuf,
    parent_identity: (u64, u64),
}

impl Fixture {
    pub fn new() -> Self {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "Linux staging tests require root for real UID/GID changes; never skip"
        );
        let test_root = protected_test_root();
        let parent_metadata = fs::symlink_metadata(&test_root).unwrap();
        let root = test_root.join(format!("apex-staging-test-{}", uuid::Uuid::now_v7()));
        private_dir(&root);
        let metadata = fs::symlink_metadata(&root).unwrap();
        let fixture = Self {
            state: root.join("state"),
            source: root.join("source"),
            identity: (metadata.dev(), metadata.ino()),
            parent_identity: (parent_metadata.dev(), parent_metadata.ino()),
            test_root,
            root,
        };
        private_dir(&fixture.state);
        private_dir(&fixture.source);
        fixture.write("health-source", HEALTH);
        fixture
    }

    pub fn write(&self, name: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.source.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    pub fn owner(&self) -> StagingOwner {
        StagingOwner::open(&self.state, &self.source).expect("trusted private roots must open")
    }

    pub fn refuse(&self, materials: &[ScopedMaterial], expected: StagingError) {
        // Each caller attempt gets its own ID: a failure may quarantine its stage.
        let instance = uuid::Uuid::now_v7().to_string();
        let result = self
            .owner()
            .stage(&target(), &instance, REVISION, LAUNCH, materials);
        assert_eq!(result.unwrap_err(), expected);
    }

    pub fn state_names(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&self.state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only our exclusively created root, with the original inode, can be removed.
        let safe = self.root.parent() == Some(self.test_root.as_path())
            && fs::symlink_metadata(&self.test_root).is_ok_and(|m| {
                m.is_dir()
                    && !m.file_type().is_symlink()
                    && (m.dev(), m.ino()) == self.parent_identity
            })
            && self
                .root
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.strip_prefix("apex-staging-test-")
                        .and_then(|id| uuid::Uuid::parse_str(id).ok())
                        .is_some()
                })
            && fs::symlink_metadata(&self.root).is_ok_and(|m| {
                m.is_dir() && !m.file_type().is_symlink() && (m.dev(), m.ino()) == self.identity
            });
        if safe && let Err(error) = remove_owned_tree(&self.root, &self.root) {
            eprintln!("owned staging fixture cleanup failed: {:?}", error.kind());
        }
    }
}

fn protected_test_root() -> PathBuf {
    let root = std::env::var_os("APEX_STAGING_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    assert!(root.is_absolute());
    assert_eq!(
        fs::canonicalize(&root).unwrap(),
        root,
        "test root must have a canonical absolute path"
    );
    for ancestor in root.ancestors() {
        let m = fs::symlink_metadata(ancestor).unwrap();
        assert!(m.is_dir() && !m.file_type().is_symlink());
        assert_eq!(m.uid(), 0, "test hierarchy must be owned by root");
        assert_eq!(
            m.mode() & 0o022,
            0,
            "test hierarchy must not be group/other writable"
        );
    }
    if root != Path::new("/") {
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o700);
    }
    root
}

fn remove_owned_tree(root: &Path, path: &Path) -> std::io::Result<()> {
    if !path.starts_with(root) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        // Sealed staged directories need write permission for test-only cleanup.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            remove_owned_tree(root, &entry?.path())?;
        }
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    }
}

pub fn assert_file(path: &Path, expected: &[u8]) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o400);
    assert_eq!(metadata.uid(), 10001);
    assert_eq!(metadata.gid(), 10001);
    assert_eq!(metadata.nlink(), 1);
    // Suppress raw-byte assertion diagnostics even for synthetic secret fixtures.
    assert!(fs::read(path).unwrap() == expected, "staged bytes differ");
}

pub fn assert_no_canary(value: &impl std::fmt::Debug) {
    let debug = format!("{value:?}");
    assert!(!debug.contains(std::str::from_utf8(CANARY).unwrap()));
}

pub fn mark_unread(path: &Path) {
    File::open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(std::time::UNIX_EPOCH))
        .unwrap();
}
