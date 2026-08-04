use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

use super::secrets::{canonical_secret_path, read_secret, read_token};
use crate::GatewayError;

const MAX_HTTP_ENDPOINT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHttpConfig {
    pub endpoint: String,
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub bearer_token_file: Option<PathBuf>,
}

impl AuthenticatedHttpConfig {
    pub fn build_client(
        &self,
        trusted_base: &Path,
    ) -> Result<(reqwest::blocking::Client, Option<Zeroizing<String>>), GatewayError> {
        crate::install_rustls_provider();
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| GatewayError::invalid_sink_configuration())?;
        if endpoint.scheme() != "https"
            || self.endpoint.len() > MAX_HTTP_ENDPOINT_BYTES
            || endpoint.host_str().is_none()
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path().to_ascii_lowercase().contains("%2f")
            || endpoint.path().to_ascii_lowercase().contains("%5c")
            || endpoint.path().to_ascii_lowercase().contains("%2e")
            || self
                .endpoint
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(GatewayError::invalid_sink_configuration());
        }
        if !safe_endpoint_host(&endpoint) {
            return Err(GatewayError::invalid_sink_configuration());
        }
        // Resolve once during trusted startup, reject any unsafe destination,
        // and pin the client to the accepted addresses. This prevents a DNS
        // answer from changing between configuration validation and request
        // dispatch (including DNS-rebinding to internal services).
        let resolved_addrs = resolve_endpoint_addrs(&endpoint)?;
        if trusted_base.is_symlink() {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let base = trusted_base
            .canonicalize()
            .map_err(|_| GatewayError::invalid_sink_configuration())?;
        if !base.is_dir() || base.is_symlink() {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let ca = read_secret(&self.ca_file, &base, false)?;
        let cert = read_secret(&self.client_cert_file, &base, false)?;
        let key = read_secret(&self.client_key_file, &base, true)?;
        let ca_path = canonical_secret_path(&self.ca_file, &base, false)?;
        let cert_path = canonical_secret_path(&self.client_cert_file, &base, false)?;
        let key_path = canonical_secret_path(&self.client_key_file, &base, true)?;
        if ca_path == cert_path || ca_path == key_path || cert_path == key_path {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let bearer_path = self
            .bearer_token_file
            .as_ref()
            .map(|path| canonical_secret_path(path, &base, true))
            .transpose()?;
        if bearer_path
            .as_ref()
            .is_some_and(|path| path == &ca_path || path == &cert_path || path == &key_path)
        {
            return Err(GatewayError::invalid_sink_configuration());
        }
        let builder = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            // Sinks must never follow an endpoint-controlled redirect with client
            // credentials or mTLS identity attached.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .map_err(|_| GatewayError::invalid_sink_configuration())?,
            )
            .identity(
                reqwest::Identity::from_pem(&[cert.as_slice(), key.as_slice()].concat())
                    .map_err(|_| GatewayError::invalid_sink_configuration())?,
            )
            .resolve_to_addrs(
                endpoint
                    .host_str()
                    .ok_or_else(GatewayError::invalid_sink_configuration)?,
                &resolved_addrs,
            );
        let token = self
            .bearer_token_file
            .as_ref()
            .map(|path| read_token(path, &base).map(Zeroizing::new))
            .transpose()?;
        let client = builder.build().map_err(|_| GatewayError::internal())?;
        Ok((client, token))
    }
}

fn resolve_endpoint_addrs(endpoint: &reqwest::Url) -> Result<Vec<SocketAddr>, GatewayError> {
    let host = endpoint
        .host_str()
        .ok_or_else(GatewayError::invalid_sink_configuration)?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(GatewayError::invalid_sink_configuration)?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| GatewayError::invalid_sink_configuration())?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || (!private_sink_destinations_explicitly_allowed(host)
            && addresses
                .iter()
                .any(|address| !safe_endpoint_address(address.ip())))
    {
        return Err(GatewayError::invalid_sink_configuration());
    }
    Ok(addresses)
}

fn private_sink_destinations_explicitly_allowed(host: &str) -> bool {
    // This is a deployment-only escape hatch for a private, service-mesh or
    // Docker network. It must never be set by event data or an API request.
    if std::env::var("APEX_ALLOW_PRIVATE_SINK_DESTINATIONS")
        .ok()
        .as_deref()
        == Some("1")
    {
        return std::env::var("APEX_PRIVATE_SINK_HOSTS")
            .ok()
            .is_some_and(|hosts| {
                hosts.split(',').any(|allowed| {
                    let allowed = allowed.trim().to_ascii_lowercase();
                    !allowed.is_empty()
                        && allowed == host.trim_end_matches('.').to_ascii_lowercase()
                })
            });
    }
    #[cfg(feature = "test-support")]
    if std::env::var("APEX_ALLOW_LOOPBACK_SINKS").ok().as_deref() == Some("1") {
        return host == "127.0.0.1" || host == "::1" || host == "localhost";
    }
    false
}

fn safe_endpoint_host(endpoint: &reqwest::Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    // Production and default builds never allow loopback/private sink endpoints.
    // Live mTLS harness builds with `test-support` may opt in explicitly so
    // provider clients can exercise 127.0.0.1 Docker port maps.
    #[cfg(feature = "test-support")]
    if std::env::var("APEX_ALLOW_LOOPBACK_SINKS").ok().as_deref() == Some("1") {
        if normalized == "localhost" || normalized.ends_with(".localhost") {
            return true;
        }
        if let Ok(address) = normalized.parse::<IpAddr>() {
            return match address {
                IpAddr::V4(value) => value.is_loopback(),
                IpAddr::V6(value) => value.is_loopback(),
            };
        }
    }
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return false;
    }
    let Ok(address) = normalized.parse::<IpAddr>() else {
        return normalized.len() <= 253
            && normalized
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
            && normalized
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    };
    safe_endpoint_address(address)
}

fn safe_endpoint_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            !value.is_loopback()
                && !value.is_private()
                && !value.is_link_local()
                && !value.is_unspecified()
                && !value.is_broadcast()
        }
        IpAddr::V6(value) => {
            !value.is_loopback()
                && !value.is_unique_local()
                && !value.is_unicast_link_local()
                && !value.is_unspecified()
        }
    }
}
