#[cfg(not(feature = "postgres"))]
use std::io;

use apex_event_ingest::{
    ArchiveHttpPublisher, AsyncNatsJetStreamClient, AuthenticatedHttpConfig,
    DurableFanoutPublisher, EventOutbox, EventPublisher, FileIdempotencyStore, FileOutbox,
    IdempotencyStore, NatsJetStreamTransport, NatsTlsConfig, RetryingDurableSink,
    RetryingJetStreamTransport, SharedOutbox,
};

use super::super::env::{optional_path, path, required};
use super::super::error::startup_gateway_error;

/// Admission's outbox+idempotency pairs -- one pair per
/// `AuthenticatedGrpcService` pool slot (Phase 0.6 item 2b; see
/// `open_durability_stores`'s doc comment for why Postgres gets
/// `admission_pool_size`-many independent pairs while file/memory always
/// get exactly one) -- and one outbox handle per fanout worker.
pub(super) type DurabilityStores = (
    Vec<(Box<dyn EventOutbox>, Box<dyn IdempotencyStore + Send>)>,
    Vec<Box<dyn EventOutbox>>,
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
pub(super) fn build_fanout_publisher(
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

/// Opens the durable outbox+idempotency pairs for the admission pool
/// (Phase 0.6 item 2b, `admission_pool_size`-many pairs) and the outbox for
/// each of the `worker_count` dedicated fanout workers (Phase 0.6 item
/// 2/3/4).
///
/// Postgres is the scale target: admission's pool members and every fanout
/// worker each get their own connection(s), and `PostgresOutbox`'s atomic
/// claim (`pending_batch`'s `SELECT ... FOR UPDATE SKIP LOCKED`, see
/// `outbox/postgres_replay.rs`) plus `PostgresIdempotencyStore`'s
/// `ON CONFLICT`-enforced uniqueness make any number of independent
/// connections safe without any in-process coordination between them --
/// raising `worker_count` or `admission_pool_size` only adds more
/// independent claimers/reservers, never a second claimer of the same row
/// or a double-accept of the same event: the database is the shared
/// consistency point, not an in-process lock.
///
/// File/memory are single-writer lab/embedded backends, not the scale
/// target: a single outbox instance is opened once and wrapped in
/// `SharedOutbox`, then cloned once per worker (plus once for admission) so
/// every actor shares the exact same in-process state instead of each
/// keeping a diverging view of the same file. `admission_pool_size` is
/// therefore IGNORED for these backends -- the returned admission pool
/// always has exactly one member, for the same reason `worker_count` is
/// ignored in favor of exactly one fanout worker below: these backends'
/// idempotency state is a local, in-process structure (a `HashMap` or a
/// file), not a shared database. N independent instances of it would not
/// coordinate at all -- each would accept and dedup against only the
/// requests it personally happened to see, silently diverging from every
/// other pool member's view and defeating idempotency entirely, which is
/// categorically worse than the contention a single shared instance
/// accepts. `APEX_ADMISSION_CONCURRENCY`'s default is conservative and
/// Postgres is the deployment this setting is meant to be raised for,
/// mirroring `APEX_FANOUT_WORKERS`.
/// The pure "how many admission pool members does this backend actually
/// get" decision `open_durability_stores` implements -- pulled out as its
/// own function so it is unit-testable without touching the filesystem,
/// Postgres, or process environment (mirrors this module's `*_value`
/// bounded-env-parse functions in spirit: the side-effect-free decision is
/// what tests exercise directly).
///
/// Postgres passes `requested` through unchanged -- it is the scale target,
/// and N independent connections are safe (see `open_durability_stores`'s
/// doc comment). File/memory always collapse to exactly 1 regardless of
/// `requested`: their idempotency/outbox state is in-process, so N
/// independent instances would each accept and dedup only the requests they
/// personally saw, diverging from one another and defeating idempotency.
pub(super) fn effective_admission_pool_size(requested: usize, is_postgres: bool) -> usize {
    if is_postgres { requested } else { 1 }
}

pub(super) fn open_durability_stores(
    capacity: usize,
    worker_count: usize,
    admission_pool_size: usize,
) -> Result<DurabilityStores, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Ok(url) = std::env::var("APEX_POSTGRES_URL")
            && !url.trim().is_empty()
        {
            let pool_size = effective_admission_pool_size(admission_pool_size, true);
            let mut admission_stores = Vec::with_capacity(pool_size);
            for _ in 0..pool_size {
                let admission_outbox = apex_event_ingest::PostgresOutbox::connect(&url, capacity)
                    .map_err(startup_gateway_error)?;
                let admission_idempotency =
                    apex_event_ingest::PostgresIdempotencyStore::connect(&url, capacity)
                        .map_err(startup_gateway_error)?;
                admission_stores.push((
                    Box::new(admission_outbox) as Box<dyn EventOutbox>,
                    Box::new(admission_idempotency) as Box<dyn IdempotencyStore + Send>,
                ));
            }
            let mut worker_outboxes: Vec<Box<dyn EventOutbox>> = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let worker_outbox = apex_event_ingest::PostgresOutbox::connect(&url, capacity)
                    .map_err(startup_gateway_error)?;
                worker_outboxes.push(Box::new(worker_outbox));
            }
            return Ok((admission_stores, worker_outboxes));
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
    // Exactly ONE admission pool member -- see this function's doc comment
    // and `effective_admission_pool_size` below for the pure decision this
    // implements (`admission_pool_size` itself is deliberately unused past
    // this point, the same way `worker_count` is above).
    let pool_size = effective_admission_pool_size(admission_pool_size, false);
    debug_assert_eq!(pool_size, 1);
    let idempotency_file = path("APEX_IDEMPOTENCY_FILE")?;
    let idempotency_base = path("APEX_IDEMPOTENCY_BASE")?;
    let idempotency = FileIdempotencyStore::open(&idempotency_file, &idempotency_base, capacity)
        .map_err(startup_gateway_error)?;
    let admission_stores: Vec<(Box<dyn EventOutbox>, Box<dyn IdempotencyStore + Send>)> =
        vec![(Box::new(shared), Box::new(idempotency))];
    Ok((admission_stores, worker_outboxes))
}
