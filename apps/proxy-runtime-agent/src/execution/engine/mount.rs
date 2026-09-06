//! Deployment-root-derived profiles, never an RPC/config flag override.
use super::*;
pub(super) enum Profile {
    Private,
    OwnedDaemonVolume,
}
impl Profile {
    pub(super) fn name(&self) -> &str {
        match self {
            Self::Private => "private-stage-v1",
            Self::OwnedDaemonVolume => "owned-daemon-volume-v1",
        }
    }
    pub(super) fn propagation(&self) -> &str {
        match self {
            Self::Private => "rprivate",
            Self::OwnedDaemonVolume => "rslave",
        }
    }
}
pub(super) fn select(engine: &Engine, installation: &str) -> Result<Profile, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let cancelled = AtomicBool::new(false);
    let output = engine.run(
        vec!["info".into(), "--format={{json .DockerRootDir}}".into()],
        deadline,
        &cancelled,
    )?;
    let json = inspect::Json::parse(&output)?;
    let root = json.0.as_str().ok_or(ERROR)?;
    let root = Path::new(root);
    if !root.is_absolute()
        || root.components().count() < 2
        || root
            .components()
            .skip(1)
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(ERROR);
    }
    if !engine.paths.staging_root.starts_with(root) {
        // A broad source containing the daemon root is never an ordinary stage.
        if root.starts_with(&engine.paths.staging_root) {
            return Err(ERROR);
        }
        return Ok(Profile::Private);
    }
    let volumes = root.join("volumes");
    let tail = engine
        .paths
        .staging_root
        .strip_prefix(&volumes)
        .map_err(|_| ERROR)?;
    let mut parts = tail.components();
    let Some(Component::Normal(volume)) = parts.next() else {
        return Err(ERROR);
    };
    let volume = volume.to_str().ok_or(ERROR)?;
    if volume.is_empty()
        || volume.len() > 128
        || volume.starts_with('-')
        || !volume
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || parts.next() != Some(Component::Normal(std::ffi::OsStr::new("_data")))
        || parts.next().is_none()
    {
        return Err(ERROR);
    }
    let mountpoint = volumes.join(volume).join("_data");
    let bytes = engine.run(
        vec!["volume".into(), "inspect".into(), volume.into()],
        deadline,
        &cancelled,
    )?;
    let v = inspect::Json::parse(&bytes)?;
    let a = v.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?;
    let v = &a[0];
    if v["Name"] != volume
        || v["Driver"] != "local"
        || v["Scope"] != "local"
        || !inspect::empty(&v["Options"])
        || v["Mountpoint"].as_str() != mountpoint.to_str()
        || v["Labels"]["io.apex.runtime.installation-id"] != installation
    {
        return Err(ERROR);
    }
    Ok(Profile::OwnedDaemonVolume)
}
