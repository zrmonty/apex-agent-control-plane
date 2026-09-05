use super::{BrowserError, ManagementRequest, OperatorAccess};
use crate::proto::mcp_proxy_service_client::McpProxyServiceClient;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

/// Deployment-only target and dedicated edge mTLS identity. Private material
/// is loaded by startup's trusted-secret policy, never supplied by a browser.
pub struct ManagementTransportConfig {
    pub target: String,
    pub server_name: String,
    pub ca_pem: Vec<u8>,
    pub client_certificate_pem: Vec<u8>,
    pub client_key_pem: Zeroizing<Vec<u8>>,
    pub connect_timeout: Duration,
    pub rpc_timeout: Duration,
    pub max_in_flight: usize,
}

impl ManagementTransportConfig {
    pub fn validate(&self) -> Result<(), BrowserError> {
        super::super::security::ConfiguredOrigin::parse(&self.target)
            .map_err(|_| BrowserError::Unavailable)?;
        if !valid_server_name(&self.server_name)
            || self.ca_pem.is_empty()
            || self.ca_pem.len() > 1024 * 1024
            || self.client_certificate_pem.is_empty()
            || self.client_certificate_pem.len() > 1024 * 1024
            || self.client_key_pem.is_empty()
            || self.client_key_pem.len() > 1024 * 1024
            || !(1..=256).contains(&self.max_in_flight)
            || !(Duration::from_millis(100)..=Duration::from_secs(10))
                .contains(&self.connect_timeout)
            || !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&self.rpc_timeout)
        {
            return Err(BrowserError::Unavailable);
        }
        Ok(())
    }
}

fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && (value.parse::<std::net::IpAddr>().is_ok()
            || value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
}

impl std::fmt::Debug for ManagementTransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagementTransportConfig([REDACTED])")
    }
}

#[derive(Clone)]
pub struct ManagementBridge {
    client: McpProxyServiceClient<Channel>,
    admission: Arc<Semaphore>,
    timeout: Duration,
}

impl ManagementBridge {
    pub async fn connect(config: ManagementTransportConfig) -> Result<Self, BrowserError> {
        config.validate()?;
        crate::install_rustls_provider();
        let tls = ClientTlsConfig::new()
            .domain_name(config.server_name)
            .ca_certificate(Certificate::from_pem(config.ca_pem))
            .identity(Identity::from_pem(
                config.client_certificate_pem,
                config.client_key_pem.as_slice(),
            ));
        let endpoint = Endpoint::from_shared(config.target)
            .map_err(|_| BrowserError::Unavailable)?
            .tls_config(tls)
            .map_err(|_| BrowserError::Unavailable)?
            .connect_timeout(config.connect_timeout)
            .timeout(config.rpc_timeout)
            .concurrency_limit(config.max_in_flight)
            .buffer_size(config.max_in_flight)
            .tcp_nodelay(true);
        let channel = tokio::time::timeout(config.connect_timeout, endpoint.connect())
            .await
            .map_err(|_| BrowserError::Unavailable)?
            .map_err(|_| BrowserError::Unavailable)?;
        Ok(Self::from_channel(
            channel,
            config.rpc_timeout,
            config.max_in_flight,
        ))
    }

    pub(super) fn from_channel(channel: Channel, timeout: Duration, max_in_flight: usize) -> Self {
        Self {
            client: McpProxyServiceClient::new(channel)
                .max_decoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES)
                .max_encoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES),
            admission: Arc::new(Semaphore::new(max_in_flight)),
            timeout,
        }
    }

    /// Single attempt; a timeout does not prove the server rejected a mutation.
    /// The caller retains its original UUIDv7 request ID for reconciliation.
    pub async fn forward(
        &self,
        request: ManagementRequest,
        access: &OperatorAccess,
    ) -> Result<Vec<u8>, BrowserError> {
        let _permit = self
            .admission
            .try_acquire()
            .map_err(|_| BrowserError::RateLimited)?;
        // Covers tonic readiness, channel buffering, transport and response.
        // A reconnect never becomes an application-level mutation retry.
        tokio::time::timeout(
            self.timeout,
            request
                .inner
                .forward(self.client.clone(), access, self.timeout),
        )
        .await
        .map_err(|_| BrowserError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ManagementTransportConfig {
        ManagementTransportConfig {
            target: "https://control.example:5443".into(),
            server_name: "control.example".into(),
            ca_pem: vec![1],
            client_certificate_pem: vec![2],
            client_key_pem: Zeroizing::new(vec![3]),
            connect_timeout: Duration::from_secs(2),
            rpc_timeout: Duration::from_secs(5),
            max_in_flight: 32,
        }
    }
    #[test]
    fn target_is_fixed_https_authority_and_all_identity_material_is_required() {
        assert_eq!(config().validate(), Ok(()));
        for target in [
            "http://localhost:5443",
            "https://control.example/path",
            "https://control.example?",
            "https://control.example#",
            "https://user:secret@control.example",
            "https:control.example",
            "https://control.example:",
            "https://control.example:0",
            "https://control.example\\",
            "https://control.example\n",
        ] {
            let mut value = config();
            value.target = target.into();
            assert!(value.validate().is_err(), "{target}");
            assert!(!format!("{value:?}").contains("secret"));
        }
        for field in 0..3 {
            let mut value = config();
            match field {
                0 => value.ca_pem.clear(),
                1 => value.client_certificate_pem.clear(),
                _ => value.client_key_pem.clear(),
            }
            assert!(value.validate().is_err());
        }
        let mut value = config();
        value.ca_pem = vec![0; 1024 * 1024 + 1];
        assert!(value.validate().is_err());
    }
    #[test]
    fn transport_capacity_and_timeouts_have_hard_upper_and_lower_bounds() {
        for count in [0, 257, usize::MAX] {
            let mut value = config();
            value.max_in_flight = count;
            assert!(value.validate().is_err());
        }
        for duration in [
            Duration::ZERO,
            Duration::from_millis(99),
            Duration::from_secs(11),
        ] {
            let mut value = config();
            value.connect_timeout = duration;
            assert!(value.validate().is_err());
        }
        for duration in [
            Duration::ZERO,
            Duration::from_millis(99),
            Duration::from_secs(31),
        ] {
            let mut value = config();
            value.rpc_timeout = duration;
            assert!(value.validate().is_err());
        }
        for name in [
            "",
            "name/path",
            "user@host",
            "host:443",
            "host\n",
            "*.example",
        ] {
            let mut value = config();
            value.server_name = name.into();
            assert!(value.validate().is_err());
        }
        assert_eq!(config().validate(), Ok(()));
    }
}
