use std::path::Path;
use std::time::Duration;

use super::config::NatsTlsConfig;
use super::secrets::{read_auth_file, validate_pem_material};
use crate::GatewayError;

/// Receives only a bounded, pre-validated publish request. Payload bytes are
/// intentionally opaque event data: they are never decoded as instructions,
/// logged, or rewritten at this client boundary because mutation would break
/// the canonical integrity chain.
pub trait NatsClient {
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
        // ContextBuilder spawns an acker task; it must be built while the
        // owned runtime is entered.
        let jetstream = {
            let _enter = runtime.enter();
            async_nats::jetstream::ContextBuilder::new()
                .timeout(Duration::from_secs(5))
                .ack_timeout(Duration::from_secs(10))
                .build(client)
        };
        Ok(Self { runtime, jetstream })
    }
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
