//! One fixed guard config under held no-follow descriptors. Never reads secrets.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardRoot {
    device: u64,
    inode: u64,
    mount: u64,
}
impl GuardRoot {
    pub(crate) fn validate(&self) -> Result<(), StagingError> {
        if self.inode == 0 || self.mount == 0 {
            return Err(StagingError::InvalidRoot);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardIdentity {
    root_device: u64,
    root_inode: u64,
    root_mount: u64,
    directory: String,
    file: String,
}
impl GuardIdentity {
    pub(crate) fn matches_root(&self, root: &GuardRoot) -> bool {
        (self.root_device, self.root_inode, self.root_mount)
            == (root.device, root.inode, root.mount)
    }
    pub(crate) fn validate(&self) -> Result<(), StagingError> {
        if self.root_inode == 0
            || self.root_mount == 0
            || !crate::shapes::hex_hash(&self.directory)
            || !crate::shapes::hex_hash(&self.file)
        {
            return Err(StagingError::InvalidSource);
        }
        Ok(())
    }
}
const FILE: &str = "guard-config.json";
impl Owner {
    pub(crate) fn guard_root(&self) -> Result<GuardRoot, StagingError> {
        if process::geteuid().as_raw() != self.uid {
            return Err(StagingError::Unsupported);
        }
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        let stat = fs::fstat(&self.state.fd).map_err(|_| StagingError::InvalidRoot)?;
        let mount = mount_id(&self.state.fd)?;
        self.check_guard_root(&stat, mount)?;
        let root = GuardRoot {
            device: stat.st_dev,
            inode: stat.st_ino,
            mount,
        };
        root.validate()?;
        Ok(root)
    }
    pub(crate) fn guard(
        &self,
        instance: &str,
        config: &[u8],
        recover: bool,
        expected: Option<&GuardIdentity>,
        expected_root: &GuardRoot,
        check: &mut impl FnMut() -> Result<(), &'static str>,
    ) -> Result<GuardIdentity, StagingError> {
        if process::geteuid().as_raw() != self.uid {
            return Err(StagingError::Unsupported);
        }
        if !crate::shapes::uuid_v7(instance)
            || config.is_empty()
            || config.len() > 262_144
            || std::str::from_utf8(config).is_err()
            || (!recover && expected.is_some())
        {
            return Err(StagingError::InvalidInput);
        }
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        let root = fs::fstat(&self.state.fd).map_err(|_| StagingError::InvalidRoot)?;
        let mount = mount_id(&self.state.fd)?;
        expected_root.validate()?;
        if (root.st_dev, root.st_ino, mount)
            != (
                expected_root.device,
                expected_root.inode,
                expected_root.mount,
            )
        {
            return Err(StagingError::InvalidRoot);
        }
        let name = format!("apex-guard-{instance}");
        if let Some(expected) = expected {
            expected.validate()?;
            if (root.st_dev, root.st_ino, mount)
                != (
                    expected.root_device,
                    expected.root_inode,
                    expected.root_mount,
                )
            {
                return Err(StagingError::InvalidRoot);
            }
        }
        check().map_err(|_| StagingError::Io)?;
        self.check_guard_root(&root, mount)?;
        if !recover {
            fs::mkdirat(&self.state.fd, name.as_str(), Mode::from_raw_mode(0o700))
                .map_err(|_| StagingError::AlreadyExists)?;
        }
        let directory = fs::openat(
            &self.state.fd,
            name.as_str(),
            roots::DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(|_| StagingError::InvalidSource)?;
        let initial = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        same_mount(&directory, mount)?;
        if !recover {
            if initial.st_uid != self.uid
                || initial.st_mode & 0o7777 != 0o700
                || initial.st_nlink != 2
            {
                return Err(StagingError::InvalidSource);
            }
            inventory(&directory, false)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::GuardDirectory, None)
                .map_err(|_| StagingError::Io)?;
            check().map_err(|_| StagingError::Io)?;
            self.check_guard_root(&root, mount)?;
            named(&self.state.fd, &name, &initial, mount)?;
            write_file(&directory, FILE, config)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::GuardFile, None)
                .map_err(|_| StagingError::Io)?;
            check().map_err(|_| StagingError::Io)?;
            self.check_guard_root(&root, mount)?;
            let before_seal = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
            if initial.st_dev != before_seal.st_dev
                || initial.st_ino != before_seal.st_ino
                || initial.st_uid != before_seal.st_uid
                || initial.st_mode != before_seal.st_mode
            {
                return Err(StagingError::InvalidSource);
            }
            named(&self.state.fd, &name, &before_seal, mount)?;
            inventory(&directory, true)?;
            seal(&directory, 0o500)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::GuardSealed, None)
                .map_err(|_| StagingError::Io)?;
            check().map_err(|_| StagingError::Io)?;
            self.check_guard_root(&root, mount)?;
            fs::fsync(&directory).map_err(|_| StagingError::Io)?;
            fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
        }
        check().map_err(|_| StagingError::Io)?;
        self.check_guard_root(&root, mount)?;
        let before = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::Directory
            || before.st_uid != 10001
            || before.st_gid != 10001
            || before.st_mode & 0o7777 != 0o500
            || before.st_nlink != 2
        {
            return Err(StagingError::InvalidSource);
        }
        inventory(&directory, true)?;
        let fd = fs::openat(
            &directory,
            FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StagingError::InvalidSource)?;
        same_mount(&fd, mount)?;
        let stat = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_uid != 10001
            || stat.st_gid != 10001
            || stat.st_mode & 0o7777 != 0o400
            || usize::try_from(stat.st_size).ok() != Some(config.len())
        {
            return Err(StagingError::InvalidSource);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take((config.len() + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| StagingError::Io)?;
        #[cfg(test)]
        crate::execution::testing::at(crate::execution::testing::Point::GuardRead, None)
            .map_err(|_| StagingError::Io)?;
        if bytes != config
            || !unchanged_source(&stat, &fs::fstat(&file).map_err(|_| StagingError::Io)?)
        {
            return Err(StagingError::InvalidSource);
        }
        named(&directory, FILE, &stat, mount)?;
        inventory(&directory, true)?;
        if !unchanged_source(
            &before,
            &fs::fstat(&directory).map_err(|_| StagingError::Io)?,
        ) {
            return Err(StagingError::InvalidSource);
        }
        named(&self.state.fd, &name, &before, mount)?;
        let identity = GuardIdentity {
            root_device: root.st_dev,
            root_inode: root.st_ino,
            root_mount: mount,
            directory: fingerprint(&before)?,
            file: fingerprint(&stat)?,
        };
        identity.validate()?;
        if expected.is_some_and(|expected| expected != &identity) {
            return Err(StagingError::InvalidSource);
        }
        check().map_err(|_| StagingError::Io)?;
        // Recheck after callbacks as well: a descriptor alone cannot prove its pathname.
        named(&directory, FILE, &stat, mount)?;
        named(&self.state.fd, &name, &before, mount)?;
        self.check_guard_root(&root, mount)?;
        if recover && expected.is_none() {
            // Complete permission sealing need not mean a prior process finished
            // syncing. Verify first, then durably flush before recording Sealed.
            // This does not change contents, modes, ownership, or inventory.
            fs::fsync(&file).map_err(|_| StagingError::Io)?;
            fs::fsync(&directory).map_err(|_| StagingError::Io)?;
            fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
            check().map_err(|_| StagingError::Io)?;
            named(&directory, FILE, &stat, mount)?;
            named(&self.state.fd, &name, &before, mount)?;
            self.check_guard_root(&root, mount)?;
        }
        Ok(identity)
    }
    fn check_guard_root(&self, original: &Stat, mount: u64) -> Result<(), StagingError> {
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        let current = roots::Root::open(&self.state.path, self.uid)?;
        let stat = fs::fstat(&current.fd).map_err(|_| StagingError::InvalidRoot)?;
        if (stat.st_dev, stat.st_ino) != (original.st_dev, original.st_ino) {
            return Err(StagingError::InvalidRoot);
        }
        same_mount(&current.fd, mount)
    }
}
fn inventory(directory: &impl AsFd, complete: bool) -> Result<(), StagingError> {
    let mut seen = 0;
    for entry in fs::Dir::read_from(directory).map_err(|_| StagingError::Io)? {
        let entry = entry.map_err(|_| StagingError::Io)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| StagingError::InvalidSource)?;
        if name == "." || name == ".." {
            continue;
        }
        if !complete || name != FILE || seen != 0 {
            return Err(StagingError::InvalidSource);
        }
        seen += 1;
    }
    if seen != usize::from(complete) {
        return Err(StagingError::InvalidSource);
    }
    Ok(())
}
fn same_mount(fd: &impl AsFd, mount: u64) -> Result<(), StagingError> {
    if mount_id(fd)? != mount {
        return Err(StagingError::InvalidSource);
    }
    Ok(())
}
fn named(parent: &impl AsFd, name: &str, before: &Stat, mount: u64) -> Result<(), StagingError> {
    let fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StagingError::InvalidSource)?;
    same_mount(&fd, mount)?;
    if !unchanged_source(before, &fs::fstat(&fd).map_err(|_| StagingError::Io)?) {
        return Err(StagingError::InvalidSource);
    }
    Ok(())
}
fn fingerprint(stat: &Stat) -> Result<String, StagingError> {
    let bytes = serde_json::to_vec(&(
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_nlink,
        stat.st_uid,
        stat.st_gid,
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    ))
    .map_err(|_| StagingError::InvalidSource)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
