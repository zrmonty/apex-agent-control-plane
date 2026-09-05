//! Filesystem effects remain synchronous, bounded, and relative to held FDs.

use super::{
    ScopedMaterial, StagedRuntime, StagingError,
    roots::{self, Root},
    validation,
};
use crate::proto::{RuntimeMaterialRole, RuntimeTarget};
use rustix::{
    fd::AsFd,
    fs::{self, FileType, Gid, Mode, OFlags, Stat, Uid},
    io::Errno,
    process,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_SOURCE: usize = 65_536;

pub(super) struct Owner {
    state: Root,
    source: Root,
    uid: u32,
}

impl Owner {
    pub(super) fn open(state: &Path, source: &Path) -> Result<Self, StagingError> {
        let uid = process::geteuid().as_raw();
        if !matches!(uid, 0 | 10001) {
            return Err(StagingError::Unsupported);
        }
        let state = Root::open(state, uid)?;
        let source = Root::open(source, uid)?;
        if state.overlaps(&source) {
            return Err(StagingError::InvalidRoot);
        }
        Ok(Self { state, source, uid })
    }

    pub(super) fn stage(
        &self,
        target: &RuntimeTarget,
        instance_id: &str,
        revision: &[u8],
        launch: &[u8],
        materials: &[ScopedMaterial],
    ) -> Result<StagedRuntime, StagingError> {
        if process::geteuid().as_raw() != self.uid {
            return Err(StagingError::Unsupported);
        }
        validation::request(target, instance_id, revision, launch, materials)?;
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        self.source.check(self.uid)?;

        // Read the bounded set only after validating every material's scope and
        // metadata. Each allocation stays zeroizing through all failure paths.
        let mut sources = Vec::with_capacity(materials.len());
        for material in materials {
            let bytes = read_source(&self.source, material, self.uid)?;
            sources.push((validation::filename(material.role)?, bytes));
        }
        let mut name = String::from("apex-runtime-");
        name.push_str(instance_id);
        fs::mkdirat(&self.state.fd, name.as_str(), Mode::from_raw_mode(0o700)).map_err(
            |error| {
                if error == Errno::EXIST {
                    StagingError::AlreadyExists
                } else {
                    StagingError::Io
                }
            },
        )?;
        // After successful mkdir only this new owned stage may be touched. No
        // rollback deletes it: partial files may remain quarantined for an owner.
        let directory = fs::openat(
            &self.state.fd,
            name.as_str(),
            roots::DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(|_| StagingError::Io)?;
        fs::fchmod(&directory, Mode::from_raw_mode(0o700)).map_err(|_| StagingError::Io)?;
        write_file(&directory, "runtime-revision.json", revision)?;
        write_file(&directory, "launch-context.json", launch)?;
        for (filename, bytes) in sources {
            write_file(&directory, filename, &bytes)?;
        }
        fs::fsync(&directory).map_err(|_| StagingError::Io)?;
        seal(&directory, 0o500)?;
        fs::fsync(&directory).map_err(|_| StagingError::Io)?;
        fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
        self.state.check_path(self.uid)?;
        Ok(StagedRuntime {
            directory: self.state.path.join(name),
            instance_id: instance_id.to_owned(),
        })
    }
}

fn read_source(
    root: &Root,
    material: &ScopedMaterial,
    uid: u32,
) -> Result<Zeroizing<Vec<u8>>, StagingError> {
    // NONBLOCK prevents a FIFO open from waiting before the type check.
    let fd = fs::openat(
        &root.fd,
        material.source_name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StagingError::InvalidSource)?;
    let before = fs::fstat(&fd).map_err(|_| StagingError::InvalidSource)?;
    private_source(&before, uid)?;
    let mut file = File::from(fd);
    // Allocate once at limit+1, never reallocating an owned secret buffer.
    let mut bytes = Zeroizing::new(vec![0; MAX_SOURCE + 1]);
    let mut used = 0;
    while used < bytes.len() {
        match file.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(StagingError::InvalidSource),
        }
    }
    let after = fs::fstat(&file).map_err(|_| StagingError::InvalidSource)?;
    private_source(&after, uid)?;
    if used == 0
        || used > MAX_SOURCE
        || usize::try_from(after.st_size).ok() != Some(used)
        || !unchanged_source(&before, &after)
    {
        return Err(StagingError::InvalidSource);
    }
    bytes.truncate(used);
    if material.role == RuntimeMaterialRole::HealthToken && !validation::health_token(&bytes) {
        return Err(StagingError::InvalidSource);
    }
    Ok(bytes)
}

fn private_source(stat: &Stat, uid: u32) -> Result<(), StagingError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || !roots::trusted_owner(stat.st_uid, uid)
        || !matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
        || !(1..=65_536).contains(&stat.st_size)
    {
        return Err(StagingError::InvalidSource);
    }
    Ok(())
}

fn unchanged_source(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn write_file(directory: &impl AsFd, filename: &str, bytes: &[u8]) -> Result<(), StagingError> {
    let fd = fs::openat(
        directory,
        filename,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o400),
    )
    .map_err(|_| StagingError::Io)?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|_| StagingError::Io)?;
    seal(&file, 0o400)?;
    fs::fsync(&file).map_err(|_| StagingError::Io)
}

fn seal(fd: &impl AsFd, mode: u32) -> Result<(), StagingError> {
    fs::fchown(fd, Some(Uid::from_raw(10001)), Some(Gid::from_raw(10001)))
        .map_err(|_| StagingError::Io)?;
    fs::fchmod(fd, Mode::from_raw_mode(mode)).map_err(|_| StagingError::Io)?;
    let stat = fs::fstat(fd).map_err(|_| StagingError::Io)?;
    if stat.st_uid != 10001 || stat.st_gid != 10001 || stat.st_mode & 0o7777 != mode {
        return Err(StagingError::Io);
    }
    Ok(())
}
