//! Private digest documents: no symlinks, weak ancestors or unsupported ACL claims.
use super::Refused;
use std::path::Path;

#[cfg(not(target_os = "linux"))]
pub(super) fn read(_path: &Path, _base: &Path) -> Result<Vec<u8>, Refused> {
    Err(Refused)
}

#[cfg(target_os = "linux")]
pub(super) fn read(path: &Path, base: &Path) -> Result<Vec<u8>, Refused> {
    linux::read(path, base, || {})
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{self, Mode, OFlags};
    use std::{
        fs::{File, Metadata},
        io::Read,
        os::unix::fs::MetadataExt,
        path::Component,
    };

    fn parts(path: &Path) -> Result<Vec<&std::ffi::OsStr>, Refused> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Refused);
        }
        path.components()
            .filter(|c| !matches!(c, Component::RootDir))
            .map(|c| {
                if let Component::Normal(name) = c {
                    Ok(name)
                } else {
                    Err(Refused)
                }
            })
            .collect()
    }
    fn flags(directory: bool) -> OFlags {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW;
        if directory {
            flags | OFlags::DIRECTORY
        } else {
            flags
        }
    }
    fn metadata(file: &File) -> Result<Metadata, Refused> {
        file.metadata().map_err(|_| Refused)
    }
    fn directory(meta: &Metadata, uid: u32) -> Result<(), Refused> {
        if !meta.is_dir() || ![0, uid].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err(Refused);
        }
        Ok(())
    }
    fn walk(parts: &[&std::ffi::OsStr], uid: u32) -> Result<Vec<File>, Refused> {
        let root = fs::openat(fs::CWD, "/", flags(true), Mode::empty()).map_err(|_| Refused)?;
        let mut held = vec![File::from(root)];
        directory(&metadata(&held[0])?, uid)?;
        for (index, name) in parts.iter().enumerate() {
            let is_directory = index + 1 != parts.len();
            let fd = fs::openat(
                held.last().ok_or(Refused)?,
                *name,
                flags(is_directory),
                Mode::empty(),
            )
            .map_err(|_| Refused)?;
            let file = File::from(fd);
            if is_directory {
                directory(&metadata(&file)?, uid)?;
            }
            held.push(file);
        }
        Ok(held)
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.uid() == b.uid()
            && a.gid() == b.gid()
            && a.mode() == b.mode()
            && a.len() == b.len()
            && a.nlink() == b.nlink()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    pub(super) fn read(
        path: &Path,
        base: &Path,
        after_open: impl FnOnce(),
    ) -> Result<Vec<u8>, Refused> {
        let names = parts(path)?;
        let base = parts(base)?;
        if base.is_empty() || names.len() <= base.len() || !names.starts_with(&base) {
            return Err(Refused);
        }
        let uid = rustix::process::geteuid().as_raw();
        let mut held = walk(&names, uid)?;
        let snapshots = held.iter().map(metadata).collect::<Result<Vec<_>, _>>()?;
        let before = snapshots.last().ok_or(Refused)?;
        if !before.is_file()
            || ![0, uid].contains(&before.uid())
            || before.mode() & 0o7177 != 0
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > 262_144
        {
            return Err(Refused);
        }
        after_open();
        let mut bytes = Vec::new();
        held.last_mut()
            .ok_or(Refused)?
            .take(262_145)
            .read_to_end(&mut bytes)
            .map_err(|_| Refused)?;
        if bytes.is_empty()
            || bytes.len() > 262_144
            || !same(before, &metadata(held.last().ok_or(Refused)?)?)
        {
            return Err(Refused);
        }
        let current = walk(&names, uid)?;
        for ((original, file), fresh) in snapshots.iter().zip(&held).zip(&current) {
            if !same(original, &metadata(file)?) || !same(original, &metadata(fresh)?) {
                return Err(Refused);
            }
        }
        Ok(bytes)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
