//! Trusted directory traversal: never canonicalize and reopen string paths.

use super::StagingError;
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags, Stat},
};
use std::path::{Component, Path, PathBuf};

pub(super) const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

pub(super) struct Root {
    pub(super) fd: OwnedFd,
    pub(super) path: PathBuf,
    identity: Identity,
    ancestors: Vec<Identity>,
}

impl Root {
    pub(super) fn open(path: &Path, uid: u32) -> Result<Self, StagingError> {
        if !path.is_absolute() {
            return Err(StagingError::InvalidRoot);
        }
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(StagingError::InvalidRoot);
        }
        let mut fd = fs::openat(fs::CWD, "/", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| StagingError::InvalidRoot)?;
        let mut stat = fs::fstat(&fd).map_err(|_| StagingError::InvalidRoot)?;
        trusted_directory(&stat, uid, false)?;
        let mut ancestors = vec![Identity::of(&stat)];
        let mut normalized = PathBuf::from("/");
        for component in components {
            let Component::Normal(name) = component else {
                return Err(StagingError::InvalidRoot);
            };
            let next = fs::openat(&fd, name, DIRECTORY_FLAGS, Mode::empty())
                .map_err(|_| StagingError::InvalidRoot)?;
            stat = fs::fstat(&next).map_err(|_| StagingError::InvalidRoot)?;
            trusted_directory(&stat, uid, false)?;
            ancestors.push(Identity::of(&stat));
            normalized.push(name);
            fd = next;
        }
        trusted_directory(&stat, uid, true)?;
        Ok(Self {
            fd,
            path: normalized,
            identity: Identity::of(&stat),
            ancestors,
        })
    }

    pub(super) fn overlaps(&self, other: &Self) -> bool {
        self.ancestors.contains(&other.identity) || other.ancestors.contains(&self.identity)
    }

    pub(super) fn check(&self, uid: u32) -> Result<(), StagingError> {
        let stat = fs::fstat(&self.fd).map_err(|_| StagingError::InvalidRoot)?;
        trusted_directory(&stat, uid, true)?;
        if Identity::of(&stat) != self.identity {
            return Err(StagingError::InvalidRoot);
        }
        Ok(())
    }

    pub(super) fn check_path(&self, uid: u32) -> Result<(), StagingError> {
        let current = Self::open(&self.path, uid)?;
        if current.identity != self.identity {
            return Err(StagingError::InvalidRoot);
        }
        Ok(())
    }
}

fn trusted_directory(stat: &Stat, uid: u32, final_root: bool) -> Result<(), StagingError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || !trusted_owner(stat.st_uid, uid)
        || stat.st_mode & 0o022 != 0
        || (final_root && stat.st_mode & 0o7777 != 0o700)
    {
        return Err(StagingError::InvalidRoot);
    }
    Ok(())
}

pub(super) fn trusted_owner(owner: u32, uid: u32) -> bool {
    owner == 0 || owner == uid
}
