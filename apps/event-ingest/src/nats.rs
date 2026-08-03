use std::fs;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    GatewayError, GatewayErrorCode, JetStreamTransport, MAX_ENVELOPE_BYTES,
    MAX_JETSTREAM_SUBJECT_BYTES,
};

const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

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

    fn validated(&self, trusted_base: &Path) -> Result<Self, GatewayError> {
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

fn valid_endpoint(endpoint: &str) -> bool {
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

fn validate_secret_path(
    path: &Path,
    base: &Path,
    _private_key: bool,
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
    if _private_key {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GatewayError::invalid_nats_configuration());
        }
    }
    Ok(canonical)
}

pub trait NatsClient {
    /// Receives only a bounded, pre-validated publish request. Payload bytes are
    /// intentionally opaque event data: they are never decoded as instructions,
    /// logged, or rewritten at this client boundary because mutation would break
    /// the canonical integrity chain.
    fn publish(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError>;
}

/// Concrete JetStream client backed by `async-nats`, while preserving the
/// synchronous publisher contract used by the admission gateway. The runtime
/// is owned by this value so its connection tasks remain alive for its lifetime.
pub struct AsyncNatsJetStreamClient {
    runtime: tokio::runtime::Runtime,
    jetstream: async_nats::jetstream::Context,
}

impl AsyncNatsJetStreamClient {
    pub fn connect(config: &NatsTlsConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        let config = config.validated(trusted_base)?;
        validate_pem_material(&config)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .map_err(|_| GatewayError::internal())?;
        let options = async_nats::ConnectOptions::new()
            .require_tls(true)
            .tls_first()
            .connection_timeout(Duration::from_secs(5))
            .max_reconnects(Some(8))
            .add_root_certificates(config.ca_file)
            .add_client_certificate(config.client_cert_file, config.client_key_file);
        let options = match (&config.username_file, &config.password_file) {
            (Some(username_file), Some(password_file)) => {
                let username = read_auth_file(username_file)?;
                let password = read_auth_file(password_file)?;
                options.user_and_password(username, password)
            }
            (None, None) => options,
            _ => return Err(GatewayError::invalid_nats_configuration()),
        };
        let client = runtime
            .block_on(options.connect(&config.server_url))
            .map_err(|_| GatewayError::nats_connection_failed())?;
        Ok(Self {
            runtime,
            jetstream: async_nats::jetstream::ContextBuilder::new()
                .timeout(Duration::from_secs(5))
                .ack_timeout(Duration::from_secs(10))
                .build(client),
        })
    }
}

fn read_auth_file(path: &Path) -> Result<String, GatewayError> {
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

fn validate_pem_material(config: &NatsTlsConfig) -> Result<(), GatewayError> {
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

impl NatsClient for AsyncNatsJetStreamClient {
    fn publish(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", message_id.to_owned());
        let subject = subject.to_owned();
        let publish = async {
            let ack = self
                .jetstream
                .publish_with_headers(subject, headers, payload.to_vec().into())
                .await
                .map_err(|_| GatewayError::publish_failed())?;
            ack.await.map_err(|_| GatewayError::publish_failed())
        };
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(|| self.runtime.block_on(publish))
            }
            Ok(_) => std::thread::scope(|scope| {
                scope
                    .spawn(|| self.runtime.block_on(publish))
                    .join()
                    .unwrap_or_else(|_| Err(GatewayError::internal()))
            }),
            Err(_) => self.runtime.block_on(publish),
        };
        result.map(|_| ())
    }
}

pub struct NatsJetStreamTransport<C: NatsClient> {
    client: C,
    config: NatsTlsConfig,
}

impl<C: NatsClient> NatsJetStreamTransport<C> {
    pub fn new(
        client: C,
        config: NatsTlsConfig,
        trusted_base: &Path,
    ) -> Result<Self, GatewayError> {
        let config = config.validated(trusted_base)?;
        Ok(Self { client, config })
    }

    pub fn config(&self) -> &NatsTlsConfig {
        &self.config
    }
}

impl<C: NatsClient> JetStreamTransport for NatsJetStreamTransport<C> {
    fn publish_event(
        &mut self,
        subject: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), GatewayError> {
        validate_publish_request(subject, message_id, payload)?;
        match catch_unwind(AssertUnwindSafe(|| {
            self.client.publish(subject, message_id, payload)
        })) {
            Ok(result) => result,
            Err(_) => Err(GatewayError::internal()),
        }
    }
}

fn validate_publish_request(
    subject: &str,
    message_id: &str,
    payload: &[u8],
) -> Result<(), GatewayError> {
    if !valid_publish_subject(subject) || !valid_message_id(message_id) {
        return Err(GatewayError::invalid_nats_publish_request());
    }
    if payload.is_empty() {
        return Err(GatewayError::invalid_nats_publish_request());
    }
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
    }
    Ok(())
}

fn valid_publish_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_JETSTREAM_SUBJECT_BYTES
        && subject.split('.').all(|token| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn valid_message_id(message_id: &str) -> bool {
    !message_id.is_empty()
        && message_id.len() <= 256
        && message_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_publish_validators_cover_host_and_port_edges() {
        assert!(valid_endpoint("nats.example:4222"));
        assert!(valid_endpoint("[2001:db8::1]:4222"));
        assert!(valid_endpoint("localhost"));
        for value in [
            "",
            ".host",
            "host.",
            "host:0",
            "host:abc",
            "host/path",
            "[bad]:4222",
        ] {
            assert!(!valid_endpoint(value));
        }
        assert!(valid_publish_subject("apex.workspace.prod"));
        assert!(!valid_publish_subject(""));
        assert!(!valid_publish_subject("apex..prod"));
        assert!(!valid_publish_subject("apex/../../secret"));
        assert!(valid_message_id("018f5c91:event"));
        assert!(!valid_message_id(""));
        assert!(!valid_message_id("bad id"));
    }

    #[test]
    fn auth_and_pem_readers_reject_unsafe_material() {
        let root = std::env::temp_dir().join(format!("apex-nats-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let auth = root.join("auth");
        fs::write(&auth, "user\n").unwrap();
        assert_eq!(read_auth_file(&auth).unwrap(), "user");
        fs::write(&auth, b"bad value").unwrap();
        assert!(read_auth_file(&auth).is_err());
        let ca = root.join("ca.pem");
        let cert = root.join("cert.pem");
        let key = root.join("key.pem");
        fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
        )
        .unwrap();
        fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
        )
        .unwrap();
        fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
        )
        .unwrap();
        let config = NatsTlsConfig {
            server_url: "tls://localhost:4222".to_owned(),
            ca_file: ca,
            client_cert_file: cert,
            client_key_file: key,
            username_file: None,
            password_file: None,
        };
        assert!(validate_pem_material(&config).is_ok());
        let missing = NatsTlsConfig {
            ca_file: root.join("missing"),
            ..config
        };
        assert!(validate_pem_material(&missing).is_err());
    }

    #[test]
    fn secret_paths_and_configuration_reject_escape_and_credential_mismatch() {
        let root = std::env::temp_dir().join(format!("apex-nats-path-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let ca = root.join("ca");
        let cert = root.join("cert");
        let key = root.join("key");
        fs::write(&ca, b"ca").unwrap();
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let base = root.canonicalize().unwrap();
        assert!(validate_secret_path(&ca, &base, false).is_ok());
        assert!(validate_secret_path(&root.join("missing"), &base, false).is_err());
        let config = NatsTlsConfig {
            server_url: "tls://localhost:4222".to_owned(),
            ca_file: ca,
            client_cert_file: cert,
            client_key_file: key,
            username_file: Some(root.join("user")),
            password_file: None,
        };
        assert!(config.validate(&base).is_err());
        assert!(
            NatsTlsConfig {
                server_url: "nats://localhost:4222".to_owned(),
                ..config
            }
            .validate(&base)
            .is_err()
        );
    }

    #[test]
    fn auth_reader_rejects_binary_and_oversized_values() {
        let root = std::env::temp_dir().join(format!("apex-nats-auth-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let path = root.join("auth");
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(read_auth_file(&path).is_err());
        fs::write(&path, vec![b'a'; 4097]).unwrap();
        assert!(read_auth_file(&path).is_err());
    }

    #[test]
    fn transport_constructor_preserves_validated_configuration() {
        struct Noop;
        impl NatsClient for Noop {
            fn publish(&mut self, _: &str, _: &str, _: &[u8]) -> Result<(), GatewayError> {
                Ok(())
            }
        }
        let root = std::env::temp_dir().join(format!("apex-nats-transport-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let ca = root.join("ca");
        let cert = root.join("cert");
        let key = root.join("key");
        fs::write(&ca, b"ca").unwrap();
        fs::write(&cert, b"cert").unwrap();
        fs::write(&key, b"key").unwrap();
        let config = NatsTlsConfig {
            server_url: "tls://localhost:4222".to_owned(),
            ca_file: ca,
            client_cert_file: cert,
            client_key_file: key,
            username_file: None,
            password_file: None,
        };
        let transport = NatsJetStreamTransport::new(Noop, config, &root).unwrap();
        assert_eq!(transport.config().server_url, "tls://localhost:4222");
    }

    #[test]
    fn publish_request_rejects_empty_oversized_and_invalid_inputs() {
        assert!(validate_publish_request("apex.events", "id", b"event").is_ok());
        assert_eq!(
            validate_publish_request("", "id", b"event")
                .unwrap_err()
                .code,
            GatewayErrorCode::InvalidNatsPublishRequest
        );
        assert_eq!(
            validate_publish_request("apex.events", "", b"event")
                .unwrap_err()
                .code,
            GatewayErrorCode::InvalidNatsPublishRequest
        );
        assert_eq!(
            validate_publish_request("apex.events", "id", &vec![0; MAX_ENVELOPE_BYTES + 1])
                .unwrap_err()
                .code,
            GatewayErrorCode::PayloadTooLarge
        );
    }
}
