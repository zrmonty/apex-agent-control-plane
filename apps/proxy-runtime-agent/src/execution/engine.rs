//! Typed Docker effects, no shell, start operation, context or registry helpers.
use super::record::Installed;
use crate::{
    command::{self, CommandInput},
    config::{Directory, ExecutionConfig},
    proto, shapes,
};
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, FileType, Mode, OFlags},
};
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[cfg(test)]
pub(super) mod acceptance;
mod handoff;
pub(super) mod inspect;
mod mount;
mod network;
const ERROR: &str = "RUNTIME_ENGINE_REFUSED";
pub(super) const ENV: [&str; 6] = [
    "NODE_ENV=production",
    "HOME=/tmp/apex",
    "APEX_MCP_PROFILE=managed",
    "APEX_MCP_GOVERNANCE_MODE=live",
    "APEX_RUNTIME_CONFIG_FILE=/apex/runtime/runtime-revision.json",
    "APEX_RUNTIME_LAUNCH_FILE=/apex/runtime/launch-context.json",
];
/// Test-only forwarding seam: mutate recorded observations, never the container.
#[cfg(test)]
pub(crate) fn fixture_handoff_inspect(
    installation: &str,
    installed_json: &[u8],
    inspect_json: &[u8],
    stage: &Path,
) -> Result<String, &'static str> {
    let installed: Installed = serde_json::from_slice(installed_json).map_err(|_| ERROR)?;
    inspect::check(inspect_json, installation, &installed, stage)
}
pub(super) struct Engine {
    executable: OwnedFd,
    config: Directory,
    paths: ExecutionConfig,
    socket: (u64, u64),
    mount: mount::Profile,
}
impl Engine {
    pub(super) fn open(paths: &ExecutionConfig, installation: &str) -> Result<Self, &'static str> {
        let mut value = Self {
            executable: crate::signature::linux::protected(&paths.docker_executable, false)
                .map_err(|_| ERROR)?,
            config: Directory::open(&paths.docker_config_root)?,
            socket: socket(&paths.docker_socket)?,
            paths: paths.clone(),
            mount: mount::Profile::Private,
        };
        value.check()?;
        value.mount = mount::select(&value, installation)?;
        Ok(value)
    }
    pub(super) fn mount_profile(&self) -> &str {
        self.mount.name()
    }
    fn check(&self) -> Result<(), &'static str> {
        self.config.check()?;
        if socket(&self.paths.docker_socket)? != self.socket {
            return Err(ERROR);
        }
        for e in fs::Dir::read_from(&self.config.fd).map_err(|_| ERROR)? {
            let e = e.map_err(|_| ERROR)?;
            if !matches!(e.file_name().to_bytes(), b"." | b"..") {
                return Err(ERROR);
            }
        }
        Ok(())
    }
    fn run(
        &self,
        arguments: Vec<String>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        self.check()?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::Preflight, Some(deadline))?;
        let mut args: Vec<OsString> = vec![
            format!("--host=unix://{}", self.paths.docker_socket.display()).into(),
            format!("--config={}", self.paths.docker_config_root.display()).into(),
        ];
        args.extend(arguments.into_iter().map(OsString::from));
        let executable = PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        command::run_until(
            CommandInput {
                executable: &executable,
                arguments: &args,
                directory: &self.paths.docker_config_root,
                home: None,
                budget: Duration::from_secs(30),
                cancelled,
            },
            deadline,
        )
        .map(Zeroizing::new)
        .map_err(|e| match e {
            command::CommandError::Invalid => "RUNTIME_ENGINE_COMMAND_INVALID",
            command::CommandError::Exit => "RUNTIME_ENGINE_COMMAND_EXIT",
            command::CommandError::Io => "RUNTIME_ENGINE_COMMAND_IO",
            command::CommandError::Deadline => "RUNTIME_ENGINE_COMMAND_DEADLINE",
            command::CommandError::Cancelled => "RUNTIME_ENGINE_COMMAND_CANCELLED",
            command::CommandError::OutputLimit => "RUNTIME_ENGINE_COMMAND_OUTPUT_LIMIT",
        })
    }
    pub(super) fn pull(
        &self,
        image: &crate::signature::VerifiedImage,
        b: Instant,
        c: &AtomicBool,
    ) -> Result<(), &'static str> {
        self.run(
            vec!["image".into(), "pull".into(), image.image_ref().into()],
            b,
            c,
        )?;
        Ok(())
    }
    pub(super) fn image(
        &self,
        image: &str,
        b: Instant,
        c: &AtomicBool,
    ) -> Result<(String, Vec<String>), &'static str> {
        let bytes = self.run(vec!["image".into(), "inspect".into(), image.into()], b, c)?;
        let v = inspect::Json::parse(&bytes)?;
        let a = v.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?;
        let v = &a[0];
        let id = v["Id"]
            .as_str()
            .filter(|s| shapes::image_id(s))
            .ok_or(ERROR)?;
        if !v["RepoDigests"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(image)))
            || !inspect::empty(&v["Config"]["Volumes"])
        {
            return Err(ERROR);
        }
        let mut keys = Vec::new();
        for entry in v["Config"]["Env"].as_array().ok_or(ERROR)? {
            let (key, _) = entry
                .as_str()
                .and_then(|s| s.split_once('='))
                .ok_or(ERROR)?;
            if keys.len() >= 16
                || key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(ERROR);
            }
            keys.push(key.into());
        }
        Ok((id.into(), keys))
    }
    pub(super) fn create(
        &self,
        installation: &str,
        i: &Installed,
        keys: &[String],
        b: Instant,
        c: &AtomicBool,
    ) -> Result<(), &'static str> {
        let launch: proto::RuntimeLaunchContext =
            serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
        let environment = handoff::environment(installation, i)?;
        let mut args: Vec<String> = [
            "container",
            "create",
            "--network=none",
            "--cgroupns=private",
            "--restart=no",
            "--user=10001:10001",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=268435456",
            "--memory-swap=268435456",
            "--cpus=1",
            "--pids-limit=128",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
            "--entrypoint=/usr/local/bin/node",
            "--workdir=/app/apps/mcp-gateway",
            "--no-healthcheck",
            "--log-driver=none",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.push(format!("--name=apex-runtime-{}", i.instance));
        if i.mount_profile != self.mount.name() {
            return Err(ERROR);
        }
        args.push(format!("--mount=type=bind,source={},target=/apex/runtime,readonly,bind-propagation={},bind-recursive=disabled",self.stage(i).display(),self.mount.propagation()));
        for (key, value) in inspect::labels(installation, &launch)? {
            args.push(format!("--label=io.apex.runtime.{key}={value}"));
        }
        for key in keys {
            if !environment
                .iter()
                .any(|e| e.split_once('=').is_some_and(|(k, _)| k == key))
            {
                args.push(format!("--env={key}"));
            }
        }
        for e in environment {
            args.push(format!("--env={e}"));
        }
        args.push(i.image_id.clone());
        args.push("/app/apps/mcp-gateway/dist/index.js".into());
        self.run(args, b, c)?;
        Ok(())
    }
    pub(super) fn inspect(
        &self,
        installation: &str,
        i: &Installed,
        b: Instant,
        c: &AtomicBool,
    ) -> Result<String, &'static str> {
        let bytes = self.run(
            vec![
                "container".into(),
                "inspect".into(),
                format!("apex-runtime-{}", i.instance),
            ],
            b,
            c,
        )?;
        inspect::check(&bytes, installation, i, &self.stage(i))
    }
    pub(super) fn remove(
        &self,
        i: &Installed,
        b: Instant,
        c: &AtomicBool,
    ) -> Result<(), &'static str> {
        if !shapes::hex_hash(&i.container_id) {
            return Err(ERROR);
        }
        // Dormant ownership verification proved never-started; force removal is unnecessary.
        self.run(
            vec!["container".into(), "rm".into(), i.container_id.clone()],
            b,
            c,
        )?;
        Ok(())
    }
    pub(super) fn absent(
        &self,
        i: &Installed,
        b: Instant,
        c: &AtomicBool,
    ) -> Result<bool, &'static str> {
        // Successful exact-name list is positive absence evidence; inspect failure is not.
        let bytes = self.run(
            vec![
                "container".into(),
                "ls".into(),
                "--all".into(),
                format!("--filter=name=^/apex-runtime-{}$", i.instance),
                "--format={{.ID}}".into(),
                "--no-trunc".into(),
            ],
            b,
            c,
        )?;
        Ok(bytes.iter().all(u8::is_ascii_whitespace))
    }
    fn stage(&self, i: &Installed) -> PathBuf {
        self.paths
            .staging_root
            .join(format!("apex-runtime-{}", i.instance))
    }
}
fn socket(path: &Path) -> Result<(u64, u64), &'static str> {
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(ERROR);
    }
    let mut parts = parts.peekable();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open("/", flags, Mode::empty()).map_err(|_| ERROR)?;
    while let Some(Component::Normal(name)) = parts.next() {
        let s = fs::fstat(&fd).map_err(|_| ERROR)?;
        if s.st_uid != 0 || s.st_mode & 0o022 != 0 {
            return Err(ERROR);
        }
        if parts.peek().is_none() {
            let s = fs::statat(&fd, name, fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ERROR)?;
            if FileType::from_raw_mode(s.st_mode) != FileType::Socket
                || s.st_uid != 0
                || s.st_mode & 0o002 != 0
            {
                return Err(ERROR);
            }
            return Ok((s.st_dev, s.st_ino));
        }
        fd = fs::openat(&fd, name, flags, Mode::empty()).map_err(|_| ERROR)?;
    }
    Err(ERROR)
}
