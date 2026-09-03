use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// Minimum time between full client-rebuild attempts after a publish
/// failure. `max_reconnects` below bounds `async-nats`'s own reconnect
/// budget; once it's exhausted there is no path back to a healthy
/// connection except rebuilding the client from scratch. Without this, a
/// sustained NATS outage that outlasts the reconnect budget requires a full
/// gateway process restart to recover.
const REBUILD_COOLDOWN: Duration = Duration::from_secs(10);

/// Concrete JetStream client backed by `async-nats`, while preserving the
/// synchronous publisher contract used by the admission gateway. The runtime
/// is owned by this value so its connection tasks remain alive for its lifetime.
pub struct AsyncNatsJetStreamClient {
    runtime: tokio::runtime::Runtime,
    jetstream: async_nats::jetstream::Context,
    config: NatsTlsConfig,
    trusted_base: PathBuf,
    last_rebuild_attempt: Option<Instant>,
}

impl AsyncNatsJetStreamClient {
    pub fn connect(config: &NatsTlsConfig, trusted_base: &Path) -> Result<Self, GatewayError> {
        crate::install_rustls_provider();
        let (runtime, jetstream) = Self::build(config, trusted_base)?;
        Ok(Self {
            runtime,
            jetstream,
            config: config.clone(),
            trusted_base: trusted_base.to_path_buf(),
            last_rebuild_attempt: None,
        })
    }

    fn build(
        config: &NatsTlsConfig,
        trusted_base: &Path,
    ) -> Result<(tokio::runtime::Runtime, async_nats::jetstream::Context), GatewayError> {
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
        Ok((runtime, jetstream))
    }

    /// Best-effort: rebuilds the entire client -- a fresh runtime,
    /// connection, and JetStream context -- rather than requiring an
    /// operator to restart the whole gateway process once `max_reconnects`
    /// is exhausted. Rate-limited so a sustained outage doesn't turn into a
    /// reconnect storm. A failed rebuild leaves the existing (already
    /// broken) client in place and is retried on the next cooldown window.
    fn rebuild_after_failure(&mut self) {
        let now = Instant::now();
        if self
            .last_rebuild_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < REBUILD_COOLDOWN)
        {
            return;
        }
        self.last_rebuild_attempt = Some(now);
        let config = self.config.clone();
        let trusted_base = self.trusted_base.clone();
        // `Self::build` calls `Runtime::block_on`, which panics if invoked on
        // a thread that already has a runtime entered -- and `publish` below
        // can be reached from inside `tokio::task::block_in_place`, which
        // only licenses blocking for its own duration, not nested runtime
        // construction. Run the whole rebuild on a plain, unmanaged thread so
        // it is always safe no matter how `publish` was invoked. This also
        // sidesteps a second hazard: dropping the *old* `Runtime` blocks
        // until its workers join, and Tokio panics if that join happens on a
        // thread already inside any async execution context.
        let built =
            std::thread::scope(|scope| scope.spawn(|| Self::build(&config, &trusted_base)).join());
        match built {
            Ok(Ok((runtime, jetstream))) => {
                let old_runtime = std::mem::replace(&mut self.runtime, runtime);
                self.jetstream = jetstream;
                // Drop the old runtime off-thread for the same reason the
                // rebuild itself runs off-thread: joining its workers must
                // never happen on a thread an async executor still owns.
                std::thread::spawn(move || drop(old_runtime));
                eprintln!("event-ingest nats client: rebuilt connection after a publish failure");
            }
            Ok(Err(error)) => eprintln!(
                "event-ingest nats client: rebuild attempt failed: {}: {}",
                error.code.public_code(),
                error.summary
            ),
            Err(_) => eprintln!("event-ingest nats client: rebuild attempt thread panicked"),
        }
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
        if result.is_err() {
            self.rebuild_after_failure();
        }
        result.map(|_| ())
    }
}
