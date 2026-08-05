use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(crate) fn read_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unable to read {label}"),
        )
    })?;
    let mut bytes = Vec::with_capacity(max.saturating_add(1));
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unable to read {label}"),
            )
        })?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} has an invalid size"),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_token(path: &Path, label: &str) -> Result<String, io::Error> {
    let value = String::from_utf8(read_bounded(path, 4096, label)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{label} is not UTF-8")))?
        .trim()
        .to_owned();
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || !value.is_ascii()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains invalid characters"),
        ));
    }
    Ok(value)
}

pub(crate) fn trusted_secret_path(
    path: &Path,
    base: &Path,
    max: u64,
    private: bool,
    label: &str,
) -> Result<PathBuf, io::Error> {
    if path.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must not be a symlink"),
        ));
    }
    let canonical_base = base.canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted secret base is unavailable",
        )
    })?;
    let canonical = path.canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is unavailable"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} metadata is unavailable"),
        )
    })?;
    if !canonical.starts_with(&canonical_base)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is outside the trusted secret policy"),
        ));
    }
    if private && !apex_event_ingest::permissions::private_key_permissions_restricted(&canonical) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} permissions are too broad"),
        ));
    }
    Ok(canonical)
}
