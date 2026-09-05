use super::{ImageCatalog, SignatureError as Error, VerifiedImage};
use crate::command::{self, CommandError, CommandInput};
use rustix::{
    fs::{FileType, Mode, OFlags, fstat, open, openat},
    process::geteuid,
};
use std::{
    ffi::OsString,
    os::fd::{AsRawFd, OwnedFd},
    path::{Component, Path, PathBuf},
    sync::{Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) struct Verifier {
    executable: OwnedFd,
    cache: OwnedFd,
    cache_path: PathBuf,
    pub(super) slot: Mutex<()>,
}

impl Verifier {
    pub(super) fn open(executable: &Path, cache: &Path) -> Result<Self, Error> {
        Ok(Self {
            executable: protected(executable, false)?,
            cache: protected(cache, true)?,
            cache_path: cache.to_owned(),
            slot: Mutex::new(()),
        })
    }

    pub(super) fn verify(
        &self,
        catalog: &ImageCatalog,
        id: &str,
        image: &str,
        budget: Duration,
        cancelled: &AtomicBool,
    ) -> Result<VerifiedImage, Error> {
        let started = Instant::now();
        let budget = budget.min(Duration::from_secs(30));
        let _slot = self.slot.try_lock().map_err(|_| Error::Overloaded)?;
        let selected = catalog.select(id, image).map_err(|_| Error::Catalog)?;
        // Reopen protected deployment paths and compare held cache inode; do not
        // use an attacker-chosen HOME, Docker credential helper or proxy env.
        let current = protected(&self.cache_path, true)?;
        let expected = fstat(&self.cache).map_err(|_| Error::Unavailable)?;
        let observed = fstat(&current).map_err(|_| Error::Unavailable)?;
        if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
            return Err(Error::InvalidConfiguration);
        }
        let arguments = [
            OsString::from("verify"),
            "--output=json".into(),
            "--check-claims=true".into(),
            "--max-workers=1".into(),
            "--timeout=30s".into(),
            format!(
                "--certificate-oidc-issuer={}",
                selected.certificate_oidc_issuer
            )
            .into(),
            format!("--certificate-identity={}", selected.certificate_identity).into(),
            "--".into(),
            selected.image_ref.into(),
        ];
        // Execute the held regular file, not a subsequently replaced pathname.
        // FD survives fork until exec; CLOEXEC closes it only after resolution.
        let executable = PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        let remaining = budget
            .checked_sub(started.elapsed())
            .ok_or(Error::Deadline)?;
        let output = Zeroizing::new(
            command::run(CommandInput {
                executable: &executable,
                arguments: &arguments,
                directory: &self.cache_path,
                home: Some(&self.cache_path),
                budget: remaining,
                cancelled,
            })
            .map_err(command_error)?,
        );
        super::output::check(&output, selected.image_ref)?;
        if started.elapsed() >= budget {
            return Err(Error::Deadline);
        }
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        Ok(VerifiedImage {
            image: selected.image_ref.to_owned(),
        })
    }
}

fn command_error(error: CommandError) -> Error {
    match error {
        CommandError::Cancelled => Error::Cancelled,
        CommandError::Deadline => Error::Deadline,
        CommandError::Invalid | CommandError::Io => Error::Unavailable,
        CommandError::OutputLimit | CommandError::Exit => Error::Verification,
    }
}

fn protected(path: &Path, directory: bool) -> Result<OwnedFd, Error> {
    let uid = geteuid().as_raw();
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(Error::InvalidConfiguration);
    }
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 2
        || parts
            .iter()
            .skip(1)
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::InvalidConfiguration);
    }
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd =
        open("/", directory_flags, Mode::empty()).map_err(|_| Error::InvalidConfiguration)?;
    check(&fd, true, false, uid)?;
    for (index, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(Error::InvalidConfiguration);
        };
        let final_part = index == parts.len() - 1;
        let is_dir = !final_part || directory;
        let flags = if is_dir {
            directory_flags
        } else {
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
        };
        fd = openat(&fd, *name, flags, Mode::empty()).map_err(|_| Error::InvalidConfiguration)?;
        check(&fd, is_dir, final_part, uid)?;
    }
    Ok(fd)
}

fn check(fd: &OwnedFd, directory: bool, final_part: bool, uid: u32) -> Result<(), Error> {
    let info = fstat(fd).map_err(|_| Error::InvalidConfiguration)?;
    let mode = info.st_mode & 0o7777;
    let kind = FileType::from_raw_mode(info.st_mode);
    if !matches!(info.st_uid, owner if owner == 0 || owner == uid)
        || mode & 0o6022 != 0
        || (directory && kind != FileType::Directory)
        || (!directory
            && (kind != FileType::RegularFile
                || info.st_nlink != 1
                || mode & 0o111 == 0
                || !(1..=268_435_456).contains(&info.st_size)))
        || (directory && final_part && (mode != 0o700 || info.st_uid != uid))
    {
        return Err(Error::InvalidConfiguration);
    }
    Ok(())
}
