use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) const CHILD: &str = "APEX_ROOT_BROWSER_CHILD";
pub(super) const OBSERVER: &str = "APEX_ROOT_BROWSER_OBSERVER_URL";
pub(super) const ROOT_APP: &str = "APEX_ROOT_BROWSER_APPLICATION";
pub(super) const BROWSER_ADDR: &str = "APEX_ROOT_BROWSER_HTTP_ADDR";
pub(super) const PROXY_ID: &str = "APEX_ROOT_BROWSER_PROXY_ID";
pub(super) const CLEAN: &str = "ROOT_BROWSER_CLEAN_WHILE_ALIVE";

pub(super) fn required(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .expect("required root-browser fixture setting is absent")
}

pub(in crate::startup::tests) fn require_platform() {
    #[cfg(all(windows, not(feature = "test-support")))]
    panic!(
        "Windows root tests require test-support: its explicit ACL waiver is not production permission proof"
    );
    assert!(
        std::env::var("APEX_ALLOW_POSTGRES_PLAINTEXT").as_deref() == Ok("1"),
        "the owned plaintext PG fixture requires APEX_ALLOW_POSTGRES_PLAINTEXT=1"
    );
}

// The imported HTML/PKCE driver expects super::support::Pki::trusted.
pub struct Pki {
    trusted: PathBuf,
}

impl Pki {
    pub fn require() -> Self {
        let root = PathBuf::from(required("APEX_BROWSER_TEST_PKI_DIR"))
            .canonicalize()
            .expect("required owned PKI directory is unavailable");
        let trusted = root.join("trusted-host").canonicalize().unwrap();
        assert!(trusted.is_dir() && trusted.starts_with(&root));
        Self { trusted }
    }

    pub fn trusted(&self, name: &str) -> Vec<u8> {
        assert!(matches!(
            name,
            "ca.pem"
                | "control-plane-server.pem"
                | "control-plane-server.key"
                | "control-operator-client.pem"
                | "control-operator-client.key"
                | "mcp-gateway-token"
        ));
        let path = self.trusted.join(name);
        let metadata = fs::symlink_metadata(&path).expect("required PKI file is missing");
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(path.canonicalize().unwrap().starts_with(&self.trusted));
        let mut bytes = Vec::new();
        fs::File::open(path)
            .unwrap()
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!((1..=1_048_576).contains(&bytes.len()));
        bytes
    }
}

pub(in crate::startup::tests) struct OwnedDir {
    pub path: PathBuf,
    parent: PathBuf,
    name: String,
}

impl OwnedDir {
    pub fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let name = format!("apex-root-browser-{}", uuid::Uuid::now_v7().simple());
        let path = parent.join(&name);
        fs::create_dir(&path).expect("fresh UUID directory must not exist already");
        assert_eq!(path.canonicalize().unwrap(), path);
        Self { path, parent, name }
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        assert_eq!(
            Path::new(name).file_name(),
            Some(std::ffi::OsStr::new(name))
        );
        let path = self.path.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        path
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        let expected = self.parent.join(&self.name);
        let safe = self.name.starts_with("apex-root-browser-")
            && self.path == expected
            && self.path.parent() == Some(self.parent.as_path())
            && fs::symlink_metadata(&self.path)
                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            && self.path.canonicalize().is_ok_and(|path| path == expected);
        if safe {
            if fs::remove_dir_all(&self.path).is_err() {
                eprintln!("root-browser: owned UUID directory cleanup failed");
            }
        } else {
            eprintln!("root-browser: refused cleanup of changed UUID directory");
        }
    }
}
