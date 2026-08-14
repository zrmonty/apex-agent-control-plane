use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use apex_event_ingest::{
    ArchiveHttpPublisher, AsyncNatsJetStreamClient, AuthenticatedGrpcService,
    AuthenticatedHttpConfig, AuthenticatedIngestAdapter, BearerTokenVerifier,
    DurableFanoutPublisher, EventOutbox, EventPublisher, FileIdempotencyStore, FileOutbox,
    FindingJournal, IdempotencyStore, IngestGateway, NatsJetStreamTransport, NatsTlsConfig,
    OutboxedPublisher, PendingEventReplayer, RetryingDurableSink, RetryingJetStreamTransport,
    SharedOutbox, bounded_event_ingest_server, spawn_fanout_worker,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::auth::{
    FileBearerResolver, bearer_agent_id, bearer_peer_certificate_sha256, bearer_subject,
    require_single_agent_file_bearer_ack,
};
use super::env::{
    allowed_scopes, attempts, fanout_workers, optional_path, outbox_retention_interval_secs,
    outbox_retention_secs, path, required,
};
use super::error::startup_gateway_error;
use super::secrets::{read_bounded, read_token, trusted_secret_path};

const MAX_IDEMPOTENCY_CAPACITY: usize = 1_000_000;

/// Admission's outbox handle, one outbox handle per fanout worker (see
/// `open_durability_stores`), and the idempotency store.
type DurabilityStores = (
    Box<dyn EventOutbox>,
    Vec<Box<dyn EventOutbox>>,
    Box<dyn IdempotencyStore + Send>,
);

/// Builds one complete, independently-connected JetStream/ClickHouse/archive
/// fanout stack. Called twice by `run`: once for the durable-enqueue-only
/// admission publisher (which only still needs a real fanout to satisfy
/// `OutboxedPublisher<P, O>`'s `P` and to run the one-shot pre-serve replay
/// below -- it is never invoked on the live admission path after Phase 0.6),
/// and once for the dedicated background fanout worker's own
/// `OutboxedPublisher`, so the two never share a NATS connection or HTTP
/// client and neither can stall the other.
///
/// Synchronous by design, like `run` itself: every client built here owns an
/// internal runtime and blocks on it during construction, so this must not
/// run on a thread that already has a tokio runtime entered.
fn build_fanout_publisher(
    trusted_base: &std::path::Path,
    retry_attempts: usize,
) -> Result<impl EventPublisher + Send + 'static, Box<dyn std::error::Error>> {
    let nats_config = NatsTlsConfig {
        server_url: required("APEX_NATS_URL")?,
        ca_file: path("APEX_NATS_CA_FILE")?,
        client_cert_file: path("APEX_NATS_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_NATS_CLIENT_KEY_FILE")?,
        username_file: optional_path("APEX_NATS_USERNAME_FILE")?,
        password_file: optional_path("APEX_NATS_PASSWORD_FILE")?,
    };
    let nats = AsyncNatsJetStreamClient::connect(&nats_config, trusted_base)
        .map_err(startup_gateway_error)?;
    let nats = NatsJetStreamTransport::new(nats, nats_config, trusted_base)
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
    let clickhouse = apex_event_ingest::ClickHouseHttpPublisher::new(http_base, trusted_base)
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
        ArchiveHttpPublisher::new(archive_config, trusted_base).map_err(startup_gateway_error)?;
    let archive =
        RetryingDurableSink::new(archive, retry_attempts).map_err(startup_gateway_error)?;

    Ok(DurableFanoutPublisher::new(nats, clickhouse, archive))
}

/// Opens the durable outbox for admission and for each of the `worker_count`
/// dedicated fanout workers (Phase 0.6 item 2/3/4).
///
/// Postgres is the scale target: admission and every worker each get their
/// own connection, and `PostgresOutbox`'s atomic claim (`pending_batch`'s
/// `SELECT ... FOR UPDATE SKIP LOCKED`, see `outbox/postgres_replay.rs`)
/// makes any number of independent connections safe without any in-process
/// coordination between them -- raising `worker_count` only adds more
/// independent claimers, never a second claimer of the same row.
///
/// File/memory are single-writer lab/embedded backends, not the scale
/// target: a single instance is opened once and wrapped in `SharedOutbox`,
/// then cloned once per worker (plus once for admission) so every actor
/// shares the exact same in-process state instead of each keeping a
/// diverging view of the same file. They all contend on `SharedOutbox`'s
/// mutex; that contention -- worse as `worker_count` rises -- is an accepted
/// trade-off for these backends, not something worth engineering around,
/// which is exactly why `APEX_FANOUT_WORKERS`' default is conservative and
/// Postgres is the deployment this setting is meant to be raised for.
fn open_durability_stores(
    capacity: usize,
    worker_count: usize,
) -> Result<DurabilityStores, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Ok(url) = std::env::var("APEX_POSTGRES_URL")
            && !url.trim().is_empty()
        {
            let admission_outbox = apex_event_ingest::PostgresOutbox::connect(&url, capacity)
                .map_err(startup_gateway_error)?;
            let mut worker_outboxes: Vec<Box<dyn EventOutbox>> = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let worker_outbox = apex_event_ingest::PostgresOutbox::connect(&url, capacity)
                    .map_err(startup_gateway_error)?;
                worker_outboxes.push(Box::new(worker_outbox));
            }
            let idempotency = apex_event_ingest::PostgresIdempotencyStore::connect(&url, capacity)
                .map_err(startup_gateway_error)?;
            return Ok((Box::new(admission_outbox), worker_outboxes, Box::new(idempotency)));
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
    let shared: Box<dyn EventOutbox> = Box::new(outbox);
    let shared = SharedOutbox::new(shared);
    // File/memory backends run exactly ONE fanout worker regardless of
    // `worker_count`. Unlike Postgres -- whose `pending_batch` claims rows
    // with `FOR UPDATE SKIP LOCKED`, so N connections claim disjoint rows --
    // these backends' `pending()` does not lease/claim, and `SharedOutbox`'s
    // mutex is released during the slow fanout, so two workers would both see
    // and both fan out the same pending rows. The idempotent sinks would dedup
    // the eventual landing, but the double-fanout is pure waste (and a
    // projection query could briefly observe a duplicate ClickHouse row before
    // its ReplacingMergeTree merges) on a single-instance lab backend that
    // gains nothing from concurrency. Horizontal fanout concurrency is a
    // Postgres-only (scale-target) capability.
    let _ = worker_count;
    let worker_outboxes: Vec<Box<dyn EventOutbox>> = vec![Box::new(shared.clone())];
    let idempotency_file = path("APEX_IDEMPOTENCY_FILE")?;
    let idempotency_base = path("APEX_IDEMPOTENCY_BASE")?;
    let idempotency = FileIdempotencyStore::open(&idempotency_file, &idempotency_base, capacity)
        .map_err(startup_gateway_error)?;
    Ok((Box::new(shared), worker_outboxes, Box::new(idempotency)))
}

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    let trusted_base = path("APEX_TRUSTED_SECRET_BASE")?;
    let retry_attempts = attempts()?;
    // Validated alongside `retry_attempts`, before any network-touching
    // construction begins, like every other bounded startup setting here
    // (see `startup_rejects_invalid_retry_budget_before_network_access` in
    // `tests/startup_paths.rs`, which pins that ordering for
    // `APEX_RETRY_ATTEMPTS` -- `APEX_FANOUT_WORKERS` must fail exactly as
    // early for the same reason).
    let fanout_workers = fanout_workers()?;
    let fanout = build_fanout_publisher(&trusted_base, retry_attempts)?;
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
    let (admission_outbox, worker_outboxes, idempotency) =
        open_durability_stores(capacity, fanout_workers)?;
    let mut publisher = OutboxedPublisher::new(fanout, admission_outbox);
    // One-shot pre-serve catch-up: replays whatever was left `pending` by a
    // previous process before this one accepts any traffic, using the same
    // admission-side fanout built above. Safe to run synchronously here
    // because nothing is serving yet, so there is no concurrent admission
    // call to contend with. After this point `publisher` is enqueue-only
    // (see `OutboxedPublisher::publish` in `outbox/publisher.rs`); the
    // dedicated fanout worker below is what performs fanout from here on.
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
    // The dedicated background fanout workers (Phase 0.6 item 4: now
    // `fanout_workers`-many of them, `APEX_FANOUT_WORKERS`-controlled).
    // Each gets its own fanout publisher (an independent
    // JetStream/ClickHouse/archive stack) and its own outbox handle
    // (`worker_outboxes[i]` -- an independent Postgres connection, or a
    // distinct `SharedOutbox` clone for file/memory), so a slow archive
    // PUT+verify on one worker never blocks another worker or the admission
    // adapter's mutex. Built here, before the runtime exists, for the same
    // reason `fanout` above is: construction blocks on an internal runtime.
    // `pending_batch`'s `SELECT ... FOR UPDATE SKIP LOCKED` claim
    // (`outbox/postgres_replay.rs`) is what makes these workers safe to run
    // concurrently against the same outbox: each claims a disjoint batch, so
    // no two workers ever fan out the same row.
    let mut fanout_workers_built = Vec::with_capacity(fanout_workers);
    for worker_outbox in worker_outboxes {
        let worker_fanout = build_fanout_publisher(&trusted_base, retry_attempts)?;
        fanout_workers_built.push(OutboxedPublisher::new(worker_fanout, worker_outbox));
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
    // Validated up front like every other startup setting even though it is
    // only consumed once the runtime below spawns the retention sweep: a
    // malformed value must fail fast at startup, not silently disable the
    // sweep the first time it ticks.
    let outbox_retention_secs = outbox_retention_secs()?;
    let outbox_retention_interval_secs = outbox_retention_interval_secs()?;
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
    require_single_agent_file_bearer_ack()?;
    let agent_id = bearer_agent_id()?;
    let subject = bearer_subject(&agent_id)?;
    let bearer_peer_certificate = bearer_peer_certificate_sha256()?;
    let scopes = allowed_scopes()?;
    let ephemeral_store = build_ephemeral_store(&trusted_base)?;
    let verifier = BearerTokenVerifier::new_strict(FileBearerResolver::new(
        token,
        token_path,
        trusted_base.clone(),
        subject,
        agent_id,
        Arc::new(scopes),
        bearer_peer_certificate,
    ))
    .with_ephemeral_store(ephemeral_store.clone());
    let mut service =
        AuthenticatedGrpcService::new(AuthenticatedIngestAdapter::new(gateway), verifier);
    service = service.with_ephemeral_store(ephemeral_store);
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
    // Everything above is built without a runtime entered. The reaper and the
    // replay worker both call `tokio::spawn`/`spawn_blocking`, so they must be
    // started inside this runtime rather than during construction.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let _idempotency_reaper = spawn_idempotency_reaper(capacity)?;
        // Phase 0.6: the dedicated fanout workers are now the PRIMARY fanout
        // path, and they deliberately do not go through `service`/the
        // admission adapter mutex at all -- see `spawn_fanout_worker`'s doc
        // comment in `outbox/publisher.rs`. `AuthenticatedGrpcService::
        // spawn_replay_worker` still exists (and is still exercised by
        // tests) as a manual/fallback replay path reachable through the
        // admission adapter, but wiring it here as well would reintroduce
        // exactly the contention this refactor removes, so it is not
        // spawned in production.
        //
        // Item 4: `fanout_workers_built.len()` (== `APEX_FANOUT_WORKERS`)
        // independent workers, each on its own `spawn_blocking` thread with
        // its own outbox handle and its own fanout stack -- see
        // `open_durability_stores`/`build_fanout_publisher` above. Handles
        // are kept alive for the life of the server (dropping a
        // `JoinHandle` would detach, not cancel, but holding them is what
        // documents these tasks as intentionally long-lived rather than
        // fire-and-forget).
        let _fanout_workers: Vec<_> = fanout_workers_built
            .into_iter()
            .map(|worker| spawn_fanout_worker(worker, Duration::from_secs(5)))
            .collect();
        // See FINDING #5: `EventOutbox::maintain` was fully implemented and
        // unit-tested but had no production call site, so the outbox
        // capacity check (which counts `complete` rows identically to
        // `pending` ones) could eventually fill from settled history alone
        // and refuse all new ingest with `IDEMPOTENCY_CAPACITY`. This sweep
        // is that missing call site.
        let _outbox_retention_worker = service.spawn_outbox_retention_worker(
            Duration::from_secs(outbox_retention_interval_secs),
            outbox_retention_secs.saturating_mul(1000),
        );
        Server::builder()
            .tls_config(tls)?
            .add_service(bounded_event_ingest_server(service))
            .serve(listen)
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

/// Periodically reclaims Postgres idempotency reservations stuck `pending`
/// past any realistic fanout window (a crash between `reserve()` committing
/// and `commit()`/`abort()` running leaves a row nothing else can release,
/// since the reservation's in-process handle dies with the process). A no-op
/// when the file/memory idempotency backends are in use, since those never
/// persist a `pending` state that could outlive their own process. Uses a
/// dedicated connection so the reaper cannot starve or race the main store's
/// connection.
#[cfg(feature = "postgres")]
fn spawn_idempotency_reaper(
    capacity: usize,
) -> Result<Option<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("APEX_POSTGRES_URL") else {
        return Ok(None);
    };
    if url.trim().is_empty() {
        return Ok(None);
    }
    let interval_secs: u64 = std::env::var("APEX_IDEMPOTENCY_REAP_INTERVAL_SECS")
        .unwrap_or_else(|_| "60".to_owned())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_REAP_INTERVAL_SECS must be a positive integer",
            )
        })?;
    let max_age_secs: u64 = std::env::var("APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS")
        .unwrap_or_else(|_| "600".to_owned())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS must be a positive integer",
            )
        })?;
    if interval_secs == 0 || max_age_secs == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_IDEMPOTENCY_REAP_INTERVAL_SECS and APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS must be positive",
        )
        .into());
    }
    // The reaper's connection is established lazily inside the loop, not
    // here, so a transient Postgres hiccup at startup (or any time later)
    // can never fail or block the whole gateway coming up -- this is a
    // best-effort maintenance task, not core request-serving functionality.
    Ok(Some(tokio::task::spawn_blocking(move || {
        let mut store: Option<apex_event_ingest::PostgresIdempotencyStore> = None;
        loop {
            std::thread::sleep(Duration::from_secs(interval_secs));
            let active_store = match &mut store {
                Some(store) => store,
                None => match apex_event_ingest::PostgresIdempotencyStore::connect(&url, capacity)
                {
                    Ok(connected) => store.insert(connected),
                    Err(error) => {
                        eprintln!(
                            "event-ingest idempotency reaper: connect deferred: {}: {}",
                            error.code.public_code(),
                            error.summary
                        );
                        continue;
                    }
                },
            };
            match active_store.reap_expired(Duration::from_secs(max_age_secs)) {
                Ok(0) => {}
                Ok(count) => eprintln!(
                    "event-ingest idempotency reaper: reclaimed {count} stuck pending reservation(s)"
                ),
                Err(error) => {
                    eprintln!(
                        "event-ingest idempotency reaper: reap attempt failed: {}: {}",
                        error.code.public_code(),
                        error.summary
                    );
                    // The connection may be poisoned; drop it and reconnect
                    // fresh next cycle rather than retrying indefinitely
                    // against a connection that can never recover on its own.
                    store = None;
                }
            }
        }
    })))
}

#[cfg(not(feature = "postgres"))]
fn spawn_idempotency_reaper(
    _capacity: usize,
) -> Result<Option<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    Ok(None)
}

type SharedEphemeralStore = Arc<Mutex<Box<dyn apex_event_ingest::EphemeralStore>>>;

fn build_ephemeral_store(
    trusted_base: &std::path::Path,
) -> Result<SharedEphemeralStore, Box<dyn std::error::Error>> {
    #[cfg(feature = "valkey")]
    use apex_event_ingest::FallbackEphemeralStore;
    use apex_event_ingest::{EphemeralStore, InMemoryEphemeralStore};

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
            return Ok(Arc::new(Mutex::new(store)));
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
    Ok(Arc::new(Mutex::new(store)))
}
