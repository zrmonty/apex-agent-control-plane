//! Owned test subprocesses only. No shell, inherited APEX settings or pipe threads.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct Directory {
    pub path: PathBuf,
    parent: PathBuf,
}
impl Directory {
    pub fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let path = parent.join(format!(
            "apex-authority-client-root-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { path, parent }
    }
    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        assert!(!name.contains(['/', '\\']) && !name.contains(".."));
        let path = self.path.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options.open(&path).unwrap().write_all(bytes).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        assert_eq!(self.path.parent(), Some(self.parent.as_path()));
        assert!(
            self.path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("apex-authority-client-root-")
        );
        assert!(
            !fs::symlink_metadata(&self.path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(self.path.canonicalize().unwrap(), self.path);
        fs::remove_dir_all(&self.path).unwrap();
    }
}

pub(super) struct Process(pub Child);
impl Process {
    pub fn spawn(command: &mut Command) -> Self {
        Self(
            command
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("owned test executable must start"),
        )
    }
    pub fn finish(mut self) {
        self.0.kill().expect("terminate only owned test root");
        self.0.wait().expect("reap owned test root");
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn clean(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let upper = key.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("APEX_")
            || matches!(
                upper.as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        {
            command.env_remove(key);
        }
    }
    command.env("RUST_LOG", "off").env("RUST_BACKTRACE", "0");
}

pub(super) fn probe(command: &mut Command, directory: &Directory) -> serde_json::Value {
    let output = directory.write(&format!("output-{}.json", uuid::Uuid::now_v7()), &[]);
    let file = fs::OpenOptions::new().write(true).open(&output).unwrap();
    command.stdout(Stdio::from(file));
    let mut process = Process::spawn(command);
    let started = Instant::now();
    loop {
        assert!(
            fs::metadata(&output).unwrap().len() <= 8192,
            "probe output bound"
        );
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "probe must finish successfully, got {status}"
            );
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "probe watchdog expired"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    read_result(&output)
}

fn read_result(output: &Path) -> serde_json::Value {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(output)
        .unwrap()
        .take(8193)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8192);
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("PROBE_SECRET_CANARY") && !text.contains("PRIVATE KEY"));
    serde_json::from_slice(&bytes).unwrap()
}
