use std::io;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use apex_event_ingest::{
    ArchiveHttpPublisher, AsyncNatsJetStreamClient, AuthenticatedGrpcService,
    AuthenticatedHttpConfig, AuthenticatedIngestAdapter, BearerTokenVerifier,
    DurableFanoutPublisher, EventOutbox, FileIdempotencyStore, FileOutbox, FindingJournal,
    IdempotencyStore, IngestGateway, NatsJetStreamTransport, NatsTlsConfig, OutboxedPublisher,
    PendingEventReplayer, RetryingDurableSink, RetryingJetStreamTransport,
    bounded_event_ingest_server,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::auth::{
    FileBearerResolver, bearer_agent_id, bearer_peer_certificate_sha256, bearer_subject,
};
use super::env::{allowed_scopes, attempts, optional_path, path, required};
use super::error::startup_gateway_error;
use super::secrets::{read_bounded, read_token, trusted_secret_path};

const MAX_IDEMPOTENCY_CAPACITY: usize = 1_000_000;
type DurabilityStores = (Box<dyn EventOutbox>, Box<dyn IdempotencyStore + Send>);
type DurabilityResult = Result<DurabilityStores, Box<dyn std::error::Error>>;

pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let trusted_base = path("APEX_TRUSTED_SECRET_BASE")?;
    let retry_attempts = attempts()?;
    let nats_config = NatsTlsConfig {
        server_url: required("APEX_NATS_URL")?,
        ca_file: path("APEX_NATS_CA_FILE")?,
        client_cert_file: path("APEX_NATS_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_NATS_CLIENT_KEY_FILE")?,
        username_file: optional_path("APEX_NATS_USERNAME_FILE")?,
        password_file: optional_path("APEX_NATS_PASSWORD_FILE")?,
    };
    let nats = AsyncNatsJetStreamClient::connect(&nats_config, &trusted_base)
        .map_err(startup_gateway_error)?;
    let nats = NatsJetStreamTransport::new(nats, nats_config, &trusted_base)
        .map_err(startup_gateway_error)?;
    let nats =
        RetryingJetStreamTransport::new(nats, retry_attempts).map_err(startup_gateway_error)?;

    let http_base = AuthenticatedHttpConfig {
        endpoint: required("APEX_CLICKHOUSE_ENDPOINT")?,
        ca_file: path("APEX_CLICKHOUSE_CA_FILE")?,
        client_cert_file: path("APEX_CLICKHOUSE_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_CLICKHOUSE_CLIENT_KEY_FILE")?,
        bearer_token_file: optional_path("APEX_CLICKHOUSE_BEARER_FILE")?,
    };
    let clickhouse = apex_event_ingest::ClickHouseHttpPublisher::new(http_base, &trusted_base)
        .map_err(startup_gateway_error)?;
    let clickhouse =
        RetryingDurableSink::new(clickhouse, retry_attempts).map_err(startup_gateway_error)?;

    let archive_config = AuthenticatedHttpConfig {
        endpoint: required("APEX_ARCHIVE_ENDPOINT")?,
        ca_file: path("APEX_ARCHIVE_CA_FILE")?,
        client_cert_file: path("APEX_ARCHIVE_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_ARCHIVE_CLIENT_KEY_FILE")?,
        bearer_token_file: optional_path("APEX_ARCHIVE_BEARER_FILE")?,
    };
    let archive =
        ArchiveHttpPublisher::new(archive_config, &trusted_base).map_err(startup_gateway_error)?;
    let archive =
        RetryingDurableSink::new(archive, retry_attempts).map_err(startup_gateway_error)?;

    let fanout = DurableFanoutPublisher::new(nats, clickhouse, archive);
    let capacity = std::env::var("APEX_IDEMPOTENCY_CAPACITY")
        .unwrap_or_else(|_| "50000".to_owned())
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_CAPACITY must be a positive integer",
            )
        })?;
    if capacity == 0 || capacity > MAX_IDEMPOTENCY_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_IDEMPOTENCY_CAPACITY must be between 1 and 1000000 for the durable idempotency journal",
        )
        .into());
    }
    let (outbox, idempotency) = open_durability_stores(capacity)?;
    let mut publisher = OutboxedPublisher::new(fanout, outbox);
    if let Err(error) = publisher.replay_pending() {
        if !error.retryable {
            return Err(startup_gateway_error(error).into());
        }
        eprintln!(
            "event-ingest outbox replay deferred: {}: {}",
            error.code.public_code(),
            error.summary
        );
    }
    let alert_capacity = std::env::var("APEX_SECURITY_ALERT_CAPACITY")
        .unwrap_or_else(|_| "100000".to_owned())
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_SECURITY_ALERT_CAPACITY must be a positive integer",
            )
        })?;
    let gateway = if let Some(journal_path) = optional_path("APEX_SECURITY_FINDINGS_FILE")? {
        let journal_base = optional_path("APEX_SECURITY_FINDINGS_BASE")?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_SECURITY_FINDINGS_BASE is required when APEX_SECURITY_FINDINGS_FILE is set",
            )
        })?;
        let journal = FindingJournal::open(&journal_path, &journal_base, alert_capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        IngestGateway::with_idempotency_store(publisher, idempotency).with_security_journal(journal)
    } else {
        IngestGateway::with_idempotency_store(publisher, idempotency)
            .with_security_store(alert_capacity)
            .map_err(startup_gateway_error)?
    };
    let token_path = trusted_secret_path(
        &path("APEX_BEARER_TOKEN_FILE")?,
        &trusted_base,
        4096,
        true,
        "APEX_BEARER_TOKEN_FILE",
    )?;
    let token = Zeroizing::new(read_token(&token_path, "APEX_BEARER_TOKEN_FILE")?);
    let agent_id = bearer_agent_id()?;
    let subject = bearer_subject(&agent_id)?;
    let bearer_peer_certificate = bearer_peer_certificate_sha256()?;
    let scopes = allowed_scopes()?;
    let verifier = BearerTokenVerifier::new_strict(FileBearerResolver::new(
        token,
        token_path,
        trusted_base.clone(),
        subject,
        agent_id,
        Arc::new(scopes),
        bearer_peer_certificate,
    ));
    let mut service =
        AuthenticatedGrpcService::new(AuthenticatedIngestAdapter::new(gateway), verifier);
    service = attach_ephemeral_store(service, &trusted_base)?;
    let _replay_worker = service.spawn_replay_worker(Duration::from_secs(5));
    let server_cert_path = trusted_secret_path(
        &path("APEX_GATEWAY_SERVER_CERT_FILE")?,
        &trusted_base,
        1024 * 1024,
        false,
        "APEX_GATEWAY_SERVER_CERT_FILE",
    )?;
    let server_key_path = trusted_secret_path(
        &path("APEX_GATEWAY_SERVER_KEY_FILE")?,
        &trusted_base,
        1024 * 1024,
        true,
        "APEX_GATEWAY_SERVER_KEY_FILE",
    )?;
    let client_ca_path = trusted_secret_path(
        &path("APEX_GATEWAY_CLIENT_CA_FILE")?,
        &trusted_base,
        1024 * 1024,
        false,
        "APEX_GATEWAY_CLIENT_CA_FILE",
    )?;
    let server_cert = read_bounded(
        &server_cert_path,
        1024 * 1024,
        "APEX_GATEWAY_SERVER_CERT_FILE",
    )?;
    let server_key = read_bounded(
        &server_key_path,
        1024 * 1024,
        "APEX_GATEWAY_SERVER_KEY_FILE",
    )?;
    let client_ca = read_bounded(&client_ca_path, 1024 * 1024, "APEX_GATEWAY_CLIENT_CA_FILE")?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca))
        // Keep this explicit so a tonic upgrade cannot silently make client
        // certificates optional at the gRPC boundary.
        .client_auth_optional(false);
    let listen = required("APEX_LISTEN_ADDR")?.parse()?;
    Server::builder()
        .tls_config(tls)?
        .add_service(bounded_event_ingest_server(service))
        .serve(listen)
        .await?;
    Ok(())
}

fn open_durability_stores(capacity: usize) -> DurabilityResult {
    #[cfg(feature = "postgres")]
    {
        if let Ok(url) = std::env::var("APEX_POSTGRES_URL")
            && !url.trim().is_empty()
        {
            let outbox = apex_event_ingest::PostgresOutbox::connect(&url, capacity)
                .map_err(startup_gateway_error)?;
            let idempotency = apex_event_ingest::PostgresIdempotencyStore::connect(&url, capacity)
                .map_err(startup_gateway_error)?;
            return Ok((Box::new(outbox), Box::new(idempotency)));
        }
    }
    #[cfg(not(feature = "postgres"))]
    {
        if std::env::var("APEX_POSTGRES_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_POSTGRES_URL is set but this binary was not built with --features postgres",
            )
            .into());
        }
    }
    let outbox_file = path("APEX_OUTBOX_FILE")?;
    let outbox_base = path("APEX_OUTBOX_BASE")?;
    let outbox =
        FileOutbox::open(&outbox_file, &outbox_base, capacity).map_err(startup_gateway_error)?;
    let idempotency_file = path("APEX_IDEMPOTENCY_FILE")?;
    let idempotency_base = path("APEX_IDEMPOTENCY_BASE")?;
    let idempotency = FileIdempotencyStore::open(&idempotency_file, &idempotency_base, capacity)
        .map_err(startup_gateway_error)?;
    Ok((Box::new(outbox), Box::new(idempotency)))
}

fn attach_ephemeral_store<P, V>(
    service: AuthenticatedGrpcService<P, V>,
    trusted_base: &std::path::Path,
) -> Result<AuthenticatedGrpcService<P, V>, Box<dyn std::error::Error>>
where
    P: apex_event_ingest::EventPublisher + Send + 'static,
    V: apex_event_ingest::CallerVerifier,
{
    use apex_event_ingest::{EphemeralStore, InMemoryEphemeralStore};
    #[cfg(feature = "valkey")]
    use apex_event_ingest::FallbackEphemeralStore;
    use std::sync::Mutex;

    // Always install a process-local store. When Valkey is configured and the
    // binary is built with `--features valkey`, prefer the remote accelerator
    // and fall back to memory only on Unavailable.
    let memory = InMemoryEphemeralStore::new();

    #[cfg(feature = "valkey")]
    {
        if std::env::var("APEX_VALKEY_HOST")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
        {
            let config = apex_event_ingest::ValkeyConfig {
                host: required("APEX_VALKEY_HOST")?,
                port: std::env::var("APEX_VALKEY_PORT")
                    .unwrap_or_else(|_| "6379".to_owned())
                    .parse()
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "APEX_VALKEY_PORT must be a TCP port",
                        )
                    })?,
                username: std::env::var("APEX_VALKEY_USERNAME")
                    .unwrap_or_else(|_| "apex-ingest".to_owned()),
                password_file: path("APEX_VALKEY_PASSWORD_FILE")?,
                ca_file: path("APEX_VALKEY_CA_FILE")?,
                client_cert_file: path("APEX_VALKEY_CLIENT_CERT_FILE")?,
                client_key_file: path("APEX_VALKEY_CLIENT_KEY_FILE")?,
                trusted_base: trusted_base.to_path_buf(),
            };
            let valkey = apex_event_ingest::ValkeyEphemeralStore::connect(&config)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let store: Box<dyn EphemeralStore> =
                Box::new(FallbackEphemeralStore::new(valkey, memory));
            return Ok(service.with_ephemeral_store(Arc::new(Mutex::new(store))));
        }
    }

    #[cfg(not(feature = "valkey"))]
    {
        let _ = trusted_base;
        if std::env::var("APEX_VALKEY_HOST")
            .ok()
            .filter(|value| !value.is_empty())
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_VALKEY_HOST is set but this binary was not built with --features valkey",
            )
            .into());
        }
    }

    let store: Box<dyn EphemeralStore> = Box::new(memory);
    Ok(service.with_ephemeral_store(Arc::new(Mutex::new(store))))
}
