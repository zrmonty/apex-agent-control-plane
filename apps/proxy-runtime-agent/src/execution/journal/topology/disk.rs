use super::{Document, ERROR};
use crate::{
    config::Directory,
    execution::{metadata::strict::Object, network::hash},
};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags, Stat},
};
use std::{
    fs::File,
    io::{Read, Write},
};
const LIMIT: usize = 262_144;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    document: Object<Document>,
    checksum: String,
}
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
pub(super) fn load(root: &Directory, name: &str) -> Result<Option<Document>, &'static str> {
    root.check()?;
    if open(root, &format!("{name}.next"))?.is_some() {
        return Err(ERROR);
    }
    let Some(fd) = open(root, name)? else {
        return Ok(None);
    };
    let before = fs::fstat(&fd).map_err(|_| ERROR)?;
    if !regular(&before) || before.st_size <= 0 || before.st_size > LIMIT as i64 {
        return Err(ERROR);
    }
    let mut f = File::from(fd);
    let mut bytes = Vec::new();
    (&mut f)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR)?;
    let after = fs::fstat(&f).map_err(|_| ERROR)?;
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
    crate::execution::engine::inspect::json::Json::bounded(&bytes, LIMIT)?;
    let Object(e): Object<Envelope> = serde_json::from_slice(&bytes).map_err(|_| ERROR)?;
    e.document.0.validate()?;
    if e.checksum != hash(&e.document.0)? {
        return Err(ERROR);
    }
    root.check()?;
    Ok(Some(e.document.0))
}
pub(super) fn save(root: &Directory, name: &str, d: &Document) -> Result<(), &'static str> {
    d.validate()?;
    root.check()?;
    let bytes = serde_json::to_vec(&serde_json::json!({"document":d,"checksum":hash(d)?}))
        .map_err(|_| ERROR)?;
    if bytes.len() > LIMIT {
        return Err(ERROR);
    }
    let temp = format!("{name}.next");
    let fd = fs::openat(
        &root.fd,
        temp.as_str(),
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
    let mut f = File::from(fd);
    f.write_all(&bytes).map_err(|_| ERROR)?;
    #[cfg(test)]
    fail_at(1)?;
    fs::fsync(&f).map_err(|_| ERROR)?;
    #[cfg(test)]
    fail_at(2)?;
    fs::renameat(&root.fd, temp.as_str(), &root.fd, name).map_err(|_| ERROR)?;
    #[cfg(test)]
    fail_at(3)?;
    fs::fsync(&root.fd).map_err(|_| ERROR)?;
    root.check()
}
#[cfg(test)]
thread_local! {pub(super) static FAIL_POINT:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
#[cfg(test)]
fn fail_at(point: u8) -> Result<(), &'static str> {
    if FAIL_POINT.with(|p| {
        if p.get() == point {
            p.set(0);
            true
        } else {
            false
        }
    }) {
        Err(ERROR)
    } else {
        Ok(())
    }
}
