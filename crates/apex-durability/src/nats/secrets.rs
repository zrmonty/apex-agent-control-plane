use std::fs;
use std::io::Read;
use std::path::Path;

use super::config::NatsTlsConfig;
use crate::GatewayError;

pub(crate) const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_auth_file(path: &Path) -> Result<String, GatewayError> {
    let mut bytes = Vec::with_capacity(4097);
    fs::File::open(path)
        .map_err(|_| GatewayError::invalid_nats_configuration())?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| GatewayError::invalid_nats_configuration())?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(GatewayError::invalid_nats_configuration());
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| GatewayError::invalid_nats_configuration())?
        .trim()
        .to_owned();
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(GatewayError::invalid_nats_configuration());
    }
    Ok(value)
}

pub(crate) fn validate_pem_material(config: &NatsTlsConfig) -> Result<(), GatewayError> {
    let read_pem = |path: &Path| -> Result<String, GatewayError> {
        let mut bytes = Vec::with_capacity(MAX_TLS_MATERIAL_BYTES as usize + 1);
        fs::File::open(path)
            .map_err(|_| GatewayError::invalid_nats_configuration())?
            .take(MAX_TLS_MATERIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| GatewayError::invalid_nats_configuration())?;
        if bytes.is_empty() || bytes.len() > MAX_TLS_MATERIAL_BYTES as usize {
            return Err(GatewayError::invalid_nats_configuration());
        }
        String::from_utf8(bytes).map_err(|_| GatewayError::invalid_nats_configuration())
    };
    let ca = read_pem(&config.ca_file)?;
    let cert = read_pem(&config.client_cert_file)?;
    let key = read_pem(&config.client_key_file)?;
    if !ca.contains("-----BEGIN CERTIFICATE-----")
        || !cert.contains("-----BEGIN CERTIFICATE-----")
        || !key.contains("-----BEGIN ")
        || !key.contains(" PRIVATE KEY-----")
    {
        return Err(GatewayError::invalid_nats_configuration());
    }
    Ok(())
}
