use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
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
            .map_err(|_| sink_config_error("endpoint parse"))?;
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
            return Err(sink_config_error("endpoint shape"));
        }
        if !safe_endpoint_host(&endpoint) {
            return Err(sink_config_error("endpoint host"));
        }
        // Resolve once during trusted startup, reject any unsafe destination,
        // and pin the client to the accepted addresses. This prevents a DNS
        // answer from changing between configuration validation and request
        // dispatch (including DNS-rebinding to internal services).
        let resolved_addrs = resolve_endpoint_addrs(&endpoint)
            .map_err(|_| sink_config_error("endpoint resolution"))?;
        if trusted_base.is_symlink() {
            return Err(sink_config_error("trusted base symlink"));
        }
        let base = trusted_base
            .canonicalize()
            .map_err(|_| sink_config_error("trusted base canonicalization"))?;
        if !base.is_dir() || base.is_symlink() {
            return Err(sink_config_error("trusted base directory"));
        }
        let ca = read_secret(&self.ca_file, &base, false)
            .map_err(|_| sink_config_error("CA material"))?;
        let cert = read_secret(&self.client_cert_file, &base, false)
            .map_err(|_| sink_config_error("client certificate material"))?;
        let key = read_secret(&self.client_key_file, &base, true)
            .map_err(|_| sink_config_error("client key material"))?;
        let ca_path = canonical_secret_path(&self.ca_file, &base, false)
            .map_err(|_| sink_config_error("CA path"))?;
        let cert_path = canonical_secret_path(&self.client_cert_file, &base, false)
            .map_err(|_| sink_config_error("client certificate path"))?;
        let key_path = canonical_secret_path(&self.client_key_file, &base, true)
            .map_err(|_| sink_config_error("client key path"))?;
        if ca_path == cert_path || ca_path == key_path || cert_path == key_path {
            return Err(sink_config_error("material path collision"));
        }
        let bearer_path = self
            .bearer_token_file
            .as_ref()
            .map(|path| canonical_secret_path(path, &base, true))
            .transpose()
            .map_err(|_| sink_config_error("bearer token path"))?;
        if bearer_path
            .as_ref()
            .is_some_and(|path| path == &ca_path || path == &cert_path || path == &key_path)
        {
            return Err(sink_config_error("bearer material path collision"));
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
                    .map_err(|_| sink_config_error("CA parsing"))?,
            )
            .identity(
                reqwest::Identity::from_pem(&[cert.as_slice(), key.as_slice()].concat())
                    .map_err(|_| sink_config_error("client identity parsing"))?,
            )
            .resolve_to_addrs(
                endpoint
                    .host_str()
                    .ok_or_else(|| sink_config_error("endpoint host extraction"))?,
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

fn sink_config_error(stage: &str) -> GatewayError {
    if std::env::var("APEX_DEBUG_SINK_CONFIG").ok().as_deref() == Some("1") {
        eprintln!("event-ingest sink configuration rejected at {stage}");
    }
    GatewayError::invalid_sink_configuration()
}

fn resolve_endpoint_addrs(endpoint: &reqwest::Url) -> Result<Vec<SocketAddr>, GatewayError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| sink_config_error("endpoint host extraction"))?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| sink_config_error("endpoint port"))?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| sink_config_error("endpoint DNS resolution"))?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || (!private_sink_destinations_explicitly_allowed(host)
            && addresses
                .iter()
                .any(|address| !safe_endpoint_address(address.ip())))
    {
        return Err(sink_config_error("endpoint address policy"));
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
    #[cfg(all(feature = "test-support", debug_assertions))]
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
                && !is_carrier_grade_nat(value)
        }
        IpAddr::V6(value) => {
            // IPv4-mapped (and other IPv4-compatible) IPv6 addresses must be
            // judged by the exact same rules as their IPv4 form, not the
            // native IPv6 checks below. Otherwise an embedded address like
            // `::ffff:127.0.0.1` or `::ffff:169.254.169.254` sails past the
            // v6 checks (none of which recognize it as loopback/link-local)
            // even though it resolves straight into loopback/RFC1918/CGNAT
            // space. `to_canonical` folds IPv4-mapped IPv6 down to `V4`, so
            // recursing here reuses the IPv4 arm's full ruleset unchanged.
            if let IpAddr::V4(mapped) = value.to_canonical() {
                return safe_endpoint_address(IpAddr::V4(mapped));
            }
            !value.is_loopback()
                && !value.is_unique_local()
                && !value.is_unicast_link_local()
                && !value.is_unspecified()
                && !value.is_multicast()
        }
    }
}

/// RFC 6598 shared address space (100.64.0.0/10), used for carrier-grade NAT
/// and, by several cloud providers, for internal/shared infrastructure. Not
/// covered by `is_private`/`is_link_local`, but a sink destination resolving
/// there is just as much an SSRF-class risk as RFC 1918 space.
fn is_carrier_grade_nat(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_endpoint_address_rejects_private_link_local_and_unspecified_ranges() {
        // Deliberately excludes 127.0.0.1/::1: those are conditionally
        // exempted by APEX_ALLOW_LOOPBACK_SINKS, which may be set
        // process-wide by other tests sharing this test binary.
        for unsafe_ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "fc00::1",
            "fe80::1",
            "::",
        ] {
            let address: IpAddr = unsafe_ip.parse().unwrap();
            assert!(
                !safe_endpoint_address(address),
                "{unsafe_ip} must be rejected as an unsafe sink destination"
            );
        }
        for safe_ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let address: IpAddr = safe_ip.parse().unwrap();
            assert!(
                safe_endpoint_address(address),
                "{safe_ip} is a public address and must be allowed"
            );
        }
    }

    #[test]
    fn build_client_rejects_unsafe_endpoint_shapes_before_any_network_access() {
        let base = std::env::temp_dir();
        let cases = [
            "http://example.invalid/v1/events",
            "https://user:pass@example.invalid/v1/events",
            "https://example.invalid/v1/events?x=1",
            "https://example.invalid/v1/events#frag",
            "https://example.invalid/v1/ev\u{0}ents",
            "https://example.invalid/v1/%2e%2e/events",
            "https://example.invalid/v1/%2fevents",
        ];
        for endpoint in cases {
            let config = AuthenticatedHttpConfig {
                endpoint: endpoint.to_owned(),
                ca_file: base.join("ca.pem"),
                client_cert_file: base.join("cert.pem"),
                client_key_file: base.join("key.pem"),
                bearer_token_file: None,
            };
            assert!(
                config.build_client(&base).is_err(),
                "{endpoint} must be rejected before touching the filesystem or network"
            );
        }
        let oversized = AuthenticatedHttpConfig {
            endpoint: format!("https://example.invalid/{}", "a".repeat(600)),
            ca_file: base.join("ca.pem"),
            client_cert_file: base.join("cert.pem"),
            client_key_file: base.join("key.pem"),
            bearer_token_file: None,
        };
        assert!(oversized.build_client(&base).is_err());
    }

    #[test]
    fn build_client_rejects_private_and_cgnat_destinations_by_default() {
        let base = std::env::temp_dir();
        for endpoint in [
            "https://10.0.0.5/v1/events",
            "https://100.64.0.5/v1/events",
        ] {
            let config = AuthenticatedHttpConfig {
                endpoint: endpoint.to_owned(),
                ca_file: base.join("ca.pem"),
                client_cert_file: base.join("cert.pem"),
                client_key_file: base.join("key.pem"),
                bearer_token_file: None,
            };
            assert!(
                config.build_client(&base).is_err(),
                "{endpoint} must be rejected without the private-sink escape hatch"
            );
        }
    }

    #[test]
    fn rejects_cgnat_range_but_allows_its_boundaries() {
        for unsafe_address in ["100.64.0.0", "100.64.0.1", "100.100.1.2", "100.127.255.255"] {
            let address: Ipv4Addr = unsafe_address.parse().unwrap();
            assert!(
                !safe_endpoint_address(IpAddr::V4(address)),
                "{unsafe_address} is CGNAT space and must be rejected"
            );
        }
        for safe_address in ["100.63.255.255", "100.128.0.0", "1.1.1.1"] {
            let address: Ipv4Addr = safe_address.parse().unwrap();
            assert!(
                safe_endpoint_address(IpAddr::V4(address)),
                "{safe_address} is outside CGNAT space and should not be rejected by this check"
            );
        }
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_addresses_in_unsafe_ranges() {
        // Embedded/mapped IPv4 addresses must be judged by the same rules as
        // their plain IPv4 form (loopback, RFC1918, link-local, CGNAT), not
        // the (looser) native IPv6 checks, which don't recognize them.
        for unsafe_ip in [
            "::ffff:127.0.0.1",     // loopback
            "::ffff:10.0.0.5",      // RFC1918 private
            "::ffff:169.254.169.254", // cloud metadata endpoint
            "::ffff:100.64.0.5",    // CGNAT shared address space
        ] {
            let address: IpAddr = unsafe_ip.parse().unwrap();
            assert!(
                !safe_endpoint_address(address),
                "{unsafe_ip} is an IPv4-mapped address in unsafe space and must be rejected"
            );
        }
    }

    #[test]
    fn allows_ipv4_mapped_ipv6_address_for_public_ip() {
        // The mapped-address fix must not over-block: a mapped address whose
        // underlying IPv4 form is public should still be allowed.
        let address: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert!(
            safe_endpoint_address(address),
            "::ffff:93.184.216.34 wraps a public IPv4 address and must be allowed"
        );
    }

    #[test]
    fn rejects_ipv6_multicast_addresses() {
        let address: IpAddr = "ff02::1".parse().unwrap();
        assert!(
            !safe_endpoint_address(address),
            "ff02::1 is an IPv6 multicast address and must be rejected"
        );
    }
}
