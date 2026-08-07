//! Bounded, path-confined secret loading for the OOB control gateway.
//!
//! Deliberately a copy of the discipline in
//! `apps/event-ingest/src/startup/secrets.rs` rather than a shared import:
//! those helpers live in that binary's `startup` module, which is not part of
//! the `apex_event_ingest` library crate and therefore is not importable from
//! here. The one piece that *is* public -- the platform-specific private-key
//! permission check -- is reused rather than reimplemented
//! (`apex_event_ingest::permissions::private_key_permissions_restricted`).

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Reads at most `max` bytes, refusing an empty or oversized file. Reads
/// `max + 1` so an over-limit file is detected instead of silently truncated
/// into something that might still parse.
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

/// Reads the operator credential table.
///
/// Unlike `event-ingest`'s `read_token`, interior whitespace is allowed: the
/// table's own grammar is `token|scopes;token|scopes`, and
/// `parse_operator_token_table` trims each `;`-separated entry, so a
/// human-maintained file with one entry per line is valid input. Non-ASCII
/// and non-whitespace control characters are still refused -- a token must be
/// presentable in an `authorization: Bearer <token>` header, and the parser
/// would reject it anyway; catching it here names the file instead of
/// reporting an opaque entry index.
pub(crate) fn read_credential_table(
    path: &Path,
    max: usize,
    label: &str,
) -> Result<String, io::Error> {
    let value = String::from_utf8(read_bounded(path, max, label)?).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{label} is not UTF-8"))
    })?;
    if !value.is_ascii()
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains invalid characters"),
        ));
    }
    if value.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is empty"),
        ));
    }
    Ok(value)
}

/// Confines a configured secret path to the trusted base, refusing symlinks,
/// non-files, empty files, oversized files, and -- for private material --
/// any file whose permissions are readable beyond its owner.
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
            "APEX_CONTROL_TRUSTED_SECRET_BASE is unavailable",
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
