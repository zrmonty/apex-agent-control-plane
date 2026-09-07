//! Protected paired stage. An interrupted stage is never repaired or deleted.
use super::guard_staging::{GuardRoot, fingerprint, named, same_mount};
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
mod identity;
mod material;
pub(crate) use identity::GatewayIdentity;
pub(crate) use material::{GatewayMaterial, names};
pub(crate) struct GatewayExpected<'a> {
    pub instance: &'a str,
    pub root: &'a GuardRoot,
    pub files: &'a BTreeMap<String, String>,
    pub identity: Option<&'a GatewayIdentity>,
}

impl Owner {
    pub(crate) fn gateway_recheck(
        &self,
        instance: &str,
        root: &GuardRoot,
        identity: &GatewayIdentity,
        material: &GatewayMaterial,
    ) -> Result<(), StagingError> {
        if !crate::shapes::uuid_v7(instance) || self.guard_root()? != *root {
            return Err(StagingError::InvalidRoot);
        }
        self.gateway_sources(material)?;
        let name = format!("apex-runtime-{instance}");
        let directory = fs::openat(
            &self.state.fd,
            name.as_str(),
            roots::DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(|_| StagingError::InvalidSource)?;
        same_mount(&directory, root.mount)?;
        let stat = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        identity.check_directory(&stat, root.mount)?;
        if identity.directory.is_none() {
            return Err(StagingError::InvalidSource);
        }
        inventory(&directory, identity.files.keys().map(String::as_str))?;
        for (name, stamp) in &identity.files {
            if fingerprint(&file_stat(&directory, name, root.mount)?)? != *stamp {
                return Err(StagingError::InvalidSource);
            }
        }
        named(&self.state.fd, &name, &stat, root.mount)?;
        self.gateway_sources(material)?;
        if self.guard_root()? != *root {
            return Err(StagingError::InvalidRoot);
        }
        Ok(())
    }
    pub(crate) fn gateway(
        &self,
        material: &GatewayMaterial,
        expected: GatewayExpected<'_>,
        check: &mut impl FnMut() -> Result<(), &'static str>,
        before_seal: &mut impl FnMut(GatewayIdentity) -> Result<(), &'static str>,
    ) -> Result<GatewayIdentity, StagingError> {
        let GatewayExpected {
            instance,
            root,
            files: expected,
            identity: recover,
        } = expected;
        if !crate::shapes::uuid_v7(instance) || self.guard_root()? != *root {
            return Err(StagingError::InvalidRoot);
        }
        let root_stat = fs::fstat(&self.state.fd).map_err(|_| StagingError::Io)?;
        let mount = root.mount;
        let name = format!("apex-runtime-{instance}");
        let gate = |check: &mut dyn FnMut() -> Result<(), &'static str>| {
            check().map_err(|_| StagingError::Io)?;
            self.check_guard_root(&root_stat, mount)?;
            self.gateway_sources(material)
        };
        gate(check)?;
        if recover.is_none() {
            if material.hashes() != *expected {
                return Err(StagingError::InvalidInput);
            }
            #[cfg(test)]
            crate::execution::testing::at(
                crate::execution::testing::Point::GatewayBeforeDirectory,
                None,
            )
            .map_err(|_| StagingError::Io)?;
            gate(check)?;
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
        same_mount(&directory, mount)?;
        let initial = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        if initial.st_dev != root.device {
            return Err(StagingError::InvalidSource);
        }
        let mut identity = if let Some(identity) = recover {
            identity.check_directory(&initial, mount)?;
            identity.clone()
        } else {
            if initial.st_uid != self.uid
                || initial.st_mode & 0o7777 != 0o700
                || initial.st_nlink != 2
            {
                return Err(StagingError::InvalidSource);
            }
            inventory(&directory, std::iter::empty())?;
            let mut files = BTreeMap::new();
            for (n, b) in &material.files {
                gate(check)?;
                let current = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
                if current.st_uid != self.uid
                    || current.st_mode & 0o7777 != 0o700
                    || current.st_ino != initial.st_ino
                {
                    return Err(StagingError::InvalidSource);
                }
                named(&self.state.fd, &name, &current, mount)?;
                let stat = write_file(&directory, n, b)?;
                named(&directory, n, &stat, mount)?;
                files.insert(n.clone(), fingerprint(&stat)?);
                #[cfg(test)]
                crate::execution::testing::at(crate::execution::testing::Point::GatewayFile, None)
                    .map_err(|_| StagingError::Io)?;
            }
            gate(check)?;
            inventory(&directory, expected.keys().map(String::as_str))?;
            let identity = GatewayIdentity {
                device: initial.st_dev,
                inode: initial.st_ino,
                mount,
                files,
                directory: None,
            };
            // Record all original file identities BEFORE chmod can make this
            // complete/recoverable. No byte-identical replacement can be adopted.
            before_seal(identity.clone()).map_err(|_| StagingError::Io)?;
            gate(check)?;
            let current = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
            if current.st_uid != self.uid || current.st_mode & 0o7777 != 0o700 {
                return Err(StagingError::InvalidSource);
            }
            named(&self.state.fd, &name, &current, mount)?;
            seal(&directory, 0o500)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::GatewaySealed, None)
                .map_err(|_| StagingError::Io)?;
            identity
        };
        gate(check)?;
        let before = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        identity.check_directory(&before, mount)?;
        if before.st_uid != 10001
            || before.st_gid != 10001
            || before.st_mode & 0o7777 != 0o500
            || before.st_nlink != 2
        {
            return Err(StagingError::InvalidSource);
        }
        inventory(&directory, expected.keys().map(String::as_str))?;
        for (n, hash) in expected {
            gate(check)?;
            let fd = fs::openat(
                &directory,
                n.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| StagingError::InvalidSource)?;
            same_mount(&fd, mount)?;
            let stat = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
            let limit = match n.as_str() {
                "runtime-revision.json" => 262_144,
                "launch-context.json" | "authority-profile.json" => 16_384,
                "instance-proof" => 32,
                _ => 65_536,
            };
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_nlink != 1
                || stat.st_uid != 10001
                || stat.st_gid != 10001
                || stat.st_mode & 0o7777 != 0o400
                || stat.st_size <= 0
                || stat.st_size > limit
                || identity.files.get(n) != Some(&fingerprint(&stat)?)
            {
                return Err(StagingError::InvalidSource);
            }
            let mut file = File::from(fd);
            let mut bytes = Zeroizing::new(vec![
                0;
                usize::try_from(stat.st_size)
                    .map_err(|_| StagingError::InvalidSource)?
                    + 1
            ]);
            let mut used = 0;
            while used < bytes.len() {
                let n = file
                    .read(&mut bytes[used..])
                    .map_err(|_| StagingError::Io)?;
                if n == 0 {
                    break;
                }
                used += n;
            }
            bytes.truncate(used);
            if format!("{:x}", Sha256::digest(&*bytes)) != *hash
                || !unchanged_source(&stat, &fs::fstat(&file).map_err(|_| StagingError::Io)?)
                || (n == "instance-proof" && used != 32)
                || (n != "instance-proof" && material.files.get(n).is_none_or(|b| **b != *bytes))
            {
                return Err(StagingError::InvalidSource);
            }
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::GatewayRead, None)
                .map_err(|_| StagingError::Io)?;
            gate(check)?;
            named(&directory, n, &stat, mount)?;
            fs::fsync(&file).map_err(|_| StagingError::Io)?;
        }
        gate(check)?;
        inventory(&directory, expected.keys().map(String::as_str))?;
        named(&self.state.fd, &name, &before, mount)?;
        // Recheck every named file after all callbacks, including the final one.
        for (n, stamp) in &identity.files {
            if fingerprint(&file_stat(&directory, n, mount)?)? != *stamp {
                return Err(StagingError::InvalidSource);
            }
        }
        fs::fsync(&directory).map_err(|_| StagingError::Io)?;
        fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
        self.check_guard_root(&root_stat, mount)?;
        identity.directory = Some(fingerprint(&before)?);
        Ok(identity)
    }
}
fn file_stat(dir: &impl AsFd, name: &str, mount: u64) -> Result<Stat, StagingError> {
    let fd = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StagingError::InvalidSource)?;
    same_mount(&fd, mount)?;
    fs::fstat(&fd).map_err(|_| StagingError::Io)
}
fn inventory<'a>(
    dir: &impl AsFd,
    expected: impl Iterator<Item = &'a str>,
) -> Result<(), StagingError> {
    let expected: std::collections::BTreeSet<_> = expected.collect();
    let mut seen = 0;
    for entry in fs::Dir::read_from(dir).map_err(|_| StagingError::Io)? {
        let entry = entry.map_err(|_| StagingError::Io)?;
        let n = entry
            .file_name()
            .to_str()
            .map_err(|_| StagingError::InvalidSource)?;
        if n == "." || n == ".." {
            continue;
        }
        if !expected.contains(n) {
            return Err(StagingError::InvalidSource);
        }
        seen += 1;
    }
    if seen != expected.len() {
        return Err(StagingError::InvalidSource);
    }
    Ok(())
}
