use std::fs;
use std::path::{Path, PathBuf};

use super::secrets::MAX_TLS_MATERIAL_BYTES;
use crate::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsTlsConfig {
    pub server_url: String,
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub username_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
}

impl NatsTlsConfig {
    pub fn validate(&self, trusted_base: &Path) -> Result<(), GatewayError> {
        self.validated(trusted_base).map(|_| ())
    }

    pub(crate) fn validated(&self, trusted_base: &Path) -> Result<Self, GatewayError> {
        let Some(endpoint) = self.server_url.strip_prefix("tls://") else {
            return Err(GatewayError::invalid_nats_configuration());
        };
        if self.server_url.len() > 512 || !valid_endpoint(endpoint) {
            return Err(GatewayError::invalid_nats_configuration());
        }
        if trusted_base.is_symlink() {
            return Err(GatewayError::invalid_nats_configuration());
        }
        let base = trusted_base
            .canonicalize()
            .map_err(|_| GatewayError::invalid_nats_configuration())?;
        if !base.is_dir() {
            return Err(GatewayError::invalid_nats_configuration());
        }
        let ca_file = validate_secret_path(&self.ca_file, &base, false)?;
        let client_cert_file = validate_secret_path(&self.client_cert_file, &base, false)?;
        let client_key_file = validate_secret_path(&self.client_key_file, &base, true)?;
        let username_file = self
            .username_file
            .as_ref()
            .map(|path| validate_secret_path(path, &base, true))
            .transpose()?;
        let password_file = self
            .password_file
            .as_ref()
            .map(|path| validate_secret_path(path, &base, true))
            .transpose()?;
        if username_file.is_some() != password_file.is_some() {
            return Err(GatewayError::invalid_nats_configuration());
        }
        if ca_file == client_cert_file
            || ca_file == client_key_file
            || client_cert_file == client_key_file
        {
            return Err(GatewayError::invalid_nats_configuration());
        }
        Ok(Self {
            server_url: self.server_url.clone(),
            ca_file,
            client_cert_file,
            client_key_file,
            username_file,
            password_file,
        })
    }
}

pub(crate) fn valid_endpoint(endpoint: &str) -> bool {
    if endpoint.is_empty()
        || !endpoint.is_ascii()
        || endpoint
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || endpoint
            .chars()
            .any(|c| matches!(c, '@' | '#' | '?' | '/' | '\\'))
    {
        return false;
    }
    let (host, port, bracketed) = if endpoint.starts_with('[') {
        let Some(end) = endpoint.find(']') else {
            return false;
        };
        let rest = &endpoint[end + 1..];
        let port = rest.strip_prefix(':');
        if !rest.is_empty() && port.is_none() {
            return false;
        }
        (&endpoint[1..end], port, true)
    } else {
        let mut parts = endpoint.splitn(2, ':');
        (parts.next().unwrap_or_default(), parts.next(), false)
    };
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if bracketed {
        if host.len() > 45
            || !host.contains(':')
            || host
                .bytes()
                .any(|byte| !(byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.')))
        {
            return false;
        }
    } else if host.len() > 253
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
        || host.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return false;
    }
    port.is_none_or(|value| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u16>().is_ok_and(|port| port != 0)
    })
}

pub(crate) fn validate_secret_path(
    path: &Path,
    base: &Path,
    private_key: bool,
) -> Result<PathBuf, GatewayError> {
    if path.is_symlink() {
        return Err(GatewayError::invalid_nats_configuration());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| GatewayError::invalid_nats_configuration())?;
    if !canonical.starts_with(base) || !canonical.is_file() {
        return Err(GatewayError::invalid_nats_configuration());
    }
    let metadata =
        fs::metadata(&canonical).map_err(|_| GatewayError::invalid_nats_configuration())?;
    if metadata.len() == 0 || metadata.len() > MAX_TLS_MATERIAL_BYTES {
        return Err(GatewayError::invalid_nats_configuration());
    }
    #[cfg(unix)]
    if private_key {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GatewayError::invalid_nats_configuration());
        }
    }
    if private_key && !crate::permissions::private_key_permissions_restricted(&canonical) {
        return Err(GatewayError::invalid_nats_configuration());
    }
    Ok(canonical)
}
