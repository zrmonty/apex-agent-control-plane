//! Exact staged-file removal after durable intent and positive engine absence.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
impl Owner {
    pub(crate) fn remove_managed(
        &self,
        instance: &str,
        files: &BTreeMap<String, String>,
    ) -> Result<(), StagingError> {
        if !crate::shapes::uuid_v7(instance)
            || !(17..=50).contains(&files.len())
            || files
                .iter()
                .any(|(n, h)| !filename(n) || !crate::shapes::hex_hash(h))
        {
            return Err(StagingError::InvalidInput);
        }
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        let name = format!("apex-runtime-{instance}");
        let directory = match fs::openat(
            &self.state.fd,
            name.as_str(),
            roots::DIRECTORY_FLAGS,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(_) => return Err(StagingError::Io),
        };
        let s = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        let mount = mount_id(&directory)?;
        if s.st_uid != 10001 || s.st_gid != 10001 || !matches!(s.st_mode & 0o7777, 0o500 | 0o700) {
            return Err(StagingError::InvalidSource);
        }
        let mut present = Vec::new();
        for entry in fs::Dir::read_from(&directory).map_err(|_| StagingError::Io)? {
            let entry = entry.map_err(|_| StagingError::Io)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| StagingError::InvalidSource)?;
            if matches!(name, "." | "..") {
                continue;
            }
            let hash = files.get(name).ok_or(StagingError::InvalidSource)?;
            let fd = fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| StagingError::Io)?;
            let s = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
            if mount_id(&fd)? != mount {
                return Err(StagingError::InvalidSource);
            }
            let limit = if name == "runtime-revision.json" {
                262_144
            } else {
                65_536
            };
            if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
                || s.st_nlink != 1
                || s.st_uid != 10001
                || s.st_gid != 10001
                || s.st_mode & 0o7777 != 0o400
                || s.st_size <= 0
                || s.st_size > limit
            {
                return Err(StagingError::InvalidSource);
            }
            let mut file = File::from(fd);
            let mut bytes = Zeroizing::new(vec![0; limit as usize + 1]);
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
            if used > limit as usize
                || format!("{:x}", Sha256::digest(&bytes[..used])) != *hash
                || !unchanged_source(&s, &fs::fstat(&file).map_err(|_| StagingError::Io)?)
            {
                return Err(StagingError::InvalidSource);
            }
            present.push(name.to_owned());
        }
        // Validate the complete remaining set before the first unlink; partial
        // prior removals are allowed only because caller persisted removal intent.
        self.state.check_path(self.uid)?;
        fs::fchmod(&directory, Mode::from_raw_mode(0o700)).map_err(|_| StagingError::Io)?;
        fs::fsync(&directory).map_err(|_| StagingError::Io)?;
        for name in present {
            fs::unlinkat(&directory, name.as_str(), fs::AtFlags::empty())
                .map_err(|_| StagingError::Io)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::StageUnlink, None)
                .map_err(|_| StagingError::Io)?;
        }
        fs::fsync(&directory).map_err(|_| StagingError::Io)?;
        fs::unlinkat(&self.state.fd, name.as_str(), fs::AtFlags::REMOVEDIR)
            .map_err(|_| StagingError::Io)?;
        fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
        self.state.check_path(self.uid)
    }
}
fn filename(n: &str) -> bool {
    matches!(
        n,
        "runtime-revision.json"
            | "launch-context.json"
            | "authority-profile.json"
            | "tool-bindings.json"
            | "instance-proof"
    ) || (1..=13)
        .filter_map(|v| RuntimeMaterialRole::try_from(v).ok())
        .any(|r| validation::filename(r) == Ok(n))
        || n.strip_prefix("tool-").is_some_and(crate::shapes::hex_hash)
}
