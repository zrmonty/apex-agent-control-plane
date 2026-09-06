use super::{Document, ERROR, Envelope, Object, hash, validate};
use crate::config::Directory;
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags, Stat},
};
use std::{
    fs::File,
    io::{Read, Write},
};
pub(super) const NAME: &str = "network-reservations.json";
pub(super) const TEMP: &str = "network-reservations.json.next";
const LIMIT: usize = 65_536;
fn open(root: &Directory, name: &str) -> Result<Option<OwnedFd>, &'static str> {
    match fs::openat(
        &root.fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(ERROR),
    }
}
fn regular(s: &Stat) -> bool {
    s.st_uid == 0
        && s.st_nlink == 1
        && s.st_mode & 0o7777 == 0o600
        && FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
}
pub(super) fn load(root: &Directory) -> Result<Option<Document>, &'static str> {
    root.check()?;
    // Never discard an incomplete previous transaction or overwrite an unknown temp.
    if open(root, TEMP)?.is_some() {
        return Err(ERROR);
    }
    let Some(fd) = open(root, NAME)? else {
        return Ok(None);
    };
    let before = fs::fstat(&fd).map_err(|_| ERROR)?;
    if !regular(&before) || before.st_size <= 0 || before.st_size > LIMIT as i64 {
        return Err(ERROR);
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    (&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR)?;
    let after = fs::fstat(&file).map_err(|_| ERROR)?;
    if !regular(&after)
        || bytes.len() > LIMIT
        || bytes.len() as i64 != after.st_size
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(ERROR);
    }
    crate::execution::engine::inspect::json::Json::bounded(&bytes, LIMIT).map_err(|_| ERROR)?;
    let Object(e): Object<Envelope> = serde_json::from_slice(&bytes).map_err(|_| ERROR)?;
    if e.digest != hash(&e.document.0)? {
        return Err(ERROR);
    }
    validate(&e.document.0)?;
    root.check()?;
    Ok(Some(e.document.0))
}
pub(super) fn save(root: &Directory, d: &Document) -> Result<(), &'static str> {
    root.check()?;
    validate(d)?;
    let bytes = serde_json::to_vec(&serde_json::json!({"document":d,"digest":hash(d)?}))
        .map_err(|_| ERROR)?;
    if bytes.len() > LIMIT {
        return Err(ERROR);
    }
    let fd = fs::openat(
        &root.fd,
        TEMP,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ERROR)?;
    if !regular(&fs::fstat(&fd).map_err(|_| ERROR)?) {
        return Err(ERROR);
    }
    let mut file = File::from(fd);
    file.write_all(&bytes).map_err(|_| ERROR)?;
    fs::fsync(&file).map_err(|_| ERROR)?;
    #[cfg(test)]
    fail_at(1)?;
    fs::renameat(&root.fd, TEMP, &root.fd, NAME).map_err(|_| ERROR)?;
    #[cfg(test)]
    fail_at(2)?;
    fs::fsync(&root.fd).map_err(|_| ERROR)?;
    root.check()
}
#[cfg(test)]
thread_local! {pub(super) static FAIL_POINT:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
#[cfg(test)]
fn fail_at(point: u8) -> Result<(), &'static str> {
    if FAIL_POINT.with(|value| {
        if value.get() == point {
            value.set(0);
            true
        } else {
            false
        }
    }) {
        return Err(ERROR);
    }
    Ok(())
}
