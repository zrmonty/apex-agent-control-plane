use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::GatewayError;

const MAX_BEARER_BYTES: usize = 4096;

pub(crate) fn read_secret(
    path: &Path,
    base: &Path,
    private_key: bool,
) -> Result<Vec<u8>, GatewayError> {
    let canonical = canonical_secret_path(path, base, private_key)?;
    let file = fs::File::open(canonical).map_err(|_| GatewayError::invalid_sink_configuration())?;
    let mut bytes = Vec::with_capacity(1024 * 1024 + 1);
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GatewayError::invalid_sink_configuration())?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(bytes)
}

pub(crate) fn canonical_secret_path(
    path: &Path,
    base: &Path,
    private_key: bool,
) -> Result<PathBuf, GatewayError> {
    if path.is_symlink() {
        return Err(GatewayError::invalid_sink_configuration());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| GatewayError::invalid_sink_configuration())?;
    if !canonical.starts_with(base) || !canonical.is_file() {
        return Err(GatewayError::invalid_sink_configuration());
    }
    let metadata =
        fs::metadata(&canonical).map_err(|_| GatewayError::invalid_sink_configuration())?;
    if metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        return Err(GatewayError::invalid_sink_configuration());
    }
    if private_key && !crate::permissions::private_key_permissions_restricted(&canonical) {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(canonical)
}

pub(crate) fn read_token(path: &Path, base: &Path) -> Result<String, GatewayError> {
    let bytes = read_secret(path, base, true)?;
    let token = String::from_utf8(bytes).map_err(|_| GatewayError::invalid_sink_configuration())?;
    let token = token.trim().to_owned();
    if token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || !token.is_ascii()
        || token.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(token)
}
