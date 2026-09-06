//! Linux descriptor-relative protected configuration reads.
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags, Stat},
};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;
const ERROR: &str = "RUNTIME_CONFIG_PROTECTION";
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
pub(crate) struct Directory {
    pub(crate) fd: OwnedFd,
    path: PathBuf,
    chain: Vec<(u64, u64)>,
    uid: u32,
}
impl Directory {
    pub(crate) fn open(path: &Path) -> Result<Self, &'static str> {
        // Same root/effective-UID trust and strict final 0700 rule as staging.
        // Walk from a held root descriptor; never canonicalize then reopen.
        let uid = rustix::process::geteuid().as_raw();
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(ERROR);
        }
        let mut fd = fs::openat(fs::CWD, "/", DIR, Mode::empty()).map_err(|_| ERROR)?;
        let mut chain = vec![];
        let mut stat = fs::fstat(&fd).map_err(|_| ERROR)?;
        directory(&stat, uid)?;
        chain.push((stat.st_dev, stat.st_ino));
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(ERROR);
            };
            fd = fs::openat(&fd, name, DIR, Mode::empty()).map_err(|_| ERROR)?;
            stat = fs::fstat(&fd).map_err(|_| ERROR)?;
            directory(&stat, uid)?;
            chain.push((stat.st_dev, stat.st_ino));
            if chain.len() > 128 {
                return Err(ERROR);
            }
        }
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(ERROR);
        }
        Ok(Self {
            fd,
            path: path.into(),
            chain,
            uid,
        })
    }
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(ERROR);
        }
        let current = Self::open(&self.path)?;
        if current.chain != self.chain {
            return Err(ERROR);
        }
        let stat = fs::fstat(&self.fd).map_err(|_| ERROR)?;
        directory(&stat, self.uid)?;
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(ERROR);
        }
        Ok(())
    }
    pub(crate) fn read(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let expected = match name {
            "launch-catalog.json"
            | "authority-profiles.json"
            | "tool-bindings.json"
            | "network-catalog.json" => 262_144,
            "agent.json"
            | "peer-policy.json"
            | "image-catalog.json"
            | "server-ca.pem"
            | "server-cert.pem"
            | "server-key.pem"
            | "authority-ca.pem"
            | "authority-client-cert.pem"
            | "authority-client-key.pem" => 65_536,
            _ => return Err(ERROR),
        };
        if limit != expected {
            return Err(ERROR);
        }
        self.check()?;
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ERROR)?;
        let before = fs::fstat(&fd).map_err(|_| ERROR)?;
        regular(&before, self.uid, limit)?;
        let mut file = File::from(fd);
        let mut bytes = Zeroizing::new(vec![0; limit + 1]);
        let mut used = 0;
        while used < bytes.len() {
            match file.read(&mut bytes[used..]) {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ERROR),
            }
        }
        let after = fs::fstat(&file).map_err(|_| ERROR)?;
        regular(&after, self.uid, limit)?;
        if used == 0
            || used > limit
            || usize::try_from(after.st_size).ok() != Some(used)
            || before.st_size != after.st_size
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ERROR);
        }
        self.check()?;
        bytes.truncate(used);
        Ok(bytes)
    }
}
fn directory(s: &Stat, uid: u32) -> Result<(), &'static str> {
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || (s.st_uid != 0 && s.st_uid != uid)
        || s.st_mode & 0o022 != 0
    {
        return Err(ERROR);
    }
    Ok(())
}
fn regular(s: &Stat, uid: u32, limit: usize) -> Result<(), &'static str> {
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_nlink != 1
        || (s.st_uid != 0 && s.st_uid != uid)
        || !matches!(s.st_mode & 0o7777, 0o400 | 0o600)
        || s.st_size <= 0
        || usize::try_from(s.st_size).map_or(true, |n| n > limit)
    {
        return Err(ERROR);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
