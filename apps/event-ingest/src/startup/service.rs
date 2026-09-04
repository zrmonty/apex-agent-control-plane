#[path = "durability.rs"]
mod durability;
#[path = "support.rs"]
mod support;

use std::io;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use apex_event_ingest::{
    AuthenticatedGrpcService, AuthenticatedIngestAdapter, BearerTokenVerifier, FindingJournal,
    IngestGateway, OutboxedPublisher, PendingEventReplayer, bounded_event_ingest_server,
    spawn_fanout_worker,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::auth::{
    FileBearerResolver, bearer_agent_id, bearer_peer_certificate_sha256, bearer_subject,
    require_single_agent_file_bearer_ack,
};
use super::env::{
    admission_concurrency, allowed_scopes, attempts, backlog_alert_age_secs, backlog_alert_depth,
    backlog_monitor_interval_secs, fanout_workers, optional_path, outbox_retention_interval_secs,
    outbox_retention_secs, path, required,
};
use super::error::startup_gateway_error;
use super::secrets::{read_bounded, read_token, trusted_secret_path};

use durability::{build_fanout_publisher, open_durability_stores};
use support::{build_ephemeral_store, spawn_idempotency_reaper};

const MAX_IDEMPOTENCY_CAPACITY: usize = 1_000_000;

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
    // Phase 0.6 item 2b: validated up front like every other bounded
    // startup setting here, before any network-touching construction, for
    // the same reason `fanout_workers` is.
    let admission_concurrency = admission_concurrency()?;
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
    // Built BEFORE `open_durability_stores` -- same ordering the pre-pool
    // code used (`fanout` used to be built immediately after
    // `fanout_workers`, ahead of the file-backend outbox/idempotency paths
    // opened below) -- so a missing/invalid NATS setting is still reported
    // ahead of a missing `APEX_OUTBOX_FILE`/`APEX_IDEMPOTENCY_FILE`
    // (`tests/startup_paths.rs` pins this ordering). Reused below as pool
    // member 0's admission fanout stack rather than opening a redundant
    // extra one.
    let fanout = build_fanout_publisher(&trusted_base, retry_attempts)?;
    let (admission_stores, worker_outboxes) =
        open_durability_stores(capacity, fanout_workers, admission_concurrency)?;
    // Phase 0.6 item 2b: one admission-side fanout stack per pool member,
    // matching this module's existing "every actor gets its own
    // independently-connected stack" pattern (see `build_fanout_publisher`'s
    // doc comment) rather than sharing one fanout value across pool
    // members. In practice only the FIRST is ever exercised: after the
    // one-shot pre-serve replay just below, `OutboxedPublisher::publish` is
    // durable-enqueue-only for every pool member (see
    // `EventPublisher::publish` in `outbox/publisher.rs`), so members
    // 1..N's fanout stacks are provisioned but never invoked on the live
    // admission path -- their outbox/idempotency connections are what
    // actually matter for concurrent admission.
    let mut admission_stores = admission_stores.into_iter();
    let (first_admission_outbox, first_admission_idempotency) = admission_stores
        .next()
        .expect("admission pool has at least one member");
    let mut admission_publishers = vec![OutboxedPublisher::new(fanout, first_admission_outbox)];
    let mut admission_idempotency = vec![first_admission_idempotency];
    for (admission_outbox, admission_idem) in admission_stores {
        let admission_fanout = build_fanout_publisher(&trusted_base, retry_attempts)?;
        admission_publishers.push(OutboxedPublisher::new(admission_fanout, admission_outbox));
        admission_idempotency.push(admission_idem);
    }
    // One-shot pre-serve catch-up: replays whatever was left `pending` by a
    // previous process before this one accepts any traffic, using pool
    // member 0's admission-side fanout built above. Safe to run
    // synchronously here because nothing is serving yet, so there is no
    // concurrent admission call to contend with. This needs to run only
    // once, not once per pool member: for Postgres every member's outbox
    // connection points at the same underlying table, and for file/memory
    // there is only one member. After this point every pool member's
    // publisher is enqueue-only (see `OutboxedPublisher::publish` in
    // `outbox/publisher.rs`); the dedicated fanout workers below are what
    // perform fanout from here on.
    if let Err(error) = admission_publishers[0].replay_pending() {
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
    // PUT+verify on one worker never blocks another worker or any admission
    // pool member. Built here, before the runtime exists, for the same
    // reason the admission fanout stacks above are: construction blocks on
    // an internal runtime. `pending_batch`'s `SELECT ... FOR UPDATE SKIP
    // LOCKED` claim (`outbox/postgres_replay.rs`) is what makes these
    // workers safe to run concurrently against the same outbox: each claims
    // a disjoint batch, so no two workers ever fan out the same row.
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
    // Phase 0.6 item 6: validated up front like every other bounded startup
    // setting, even though the monitor itself only starts once the runtime
    // below spawns it.
    let backlog_monitor_interval_secs = backlog_monitor_interval_secs()?;
    let backlog_alert_depth = backlog_alert_depth()?;
    let backlog_alert_age_millis = backlog_alert_age_secs()?.saturating_mul(1000);
    // Phase 0.6 item 2b: build one `IngestGateway` per admission pool
    // member. The first one creates the (memory or journal) Security Alert
    // backend; every other member attaches the SAME backend via
    // `with_shared_security_store` (`SharedSecurityStore` is an `Arc`
    // handle -- see `gateway/core.rs`) so all N members record into and
    // read from one combined finding store instead of each maintaining its
    // own disjoint set.
    let mut admission_publishers = admission_publishers.into_iter();
    let mut admission_idempotency = admission_idempotency.into_iter();
    let first_publisher = admission_publishers
        .next()
        .expect("admission pool has at least one member");
    let first_idempotency = admission_idempotency
        .next()
        .expect("admission pool has at least one member");
    let first_gateway = if let Some(journal_path) = optional_path("APEX_SECURITY_FINDINGS_FILE")? {
        let journal_base = optional_path("APEX_SECURITY_FINDINGS_BASE")?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_SECURITY_FINDINGS_BASE is required when APEX_SECURITY_FINDINGS_FILE is set",
            )
        })?;
        let journal = FindingJournal::open(&journal_path, &journal_base, alert_capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        IngestGateway::with_idempotency_store(first_publisher, first_idempotency)
            .with_security_journal(journal)
    } else {
        IngestGateway::with_idempotency_store(first_publisher, first_idempotency)
            .with_security_store(alert_capacity)
            .map_err(startup_gateway_error)?
    };
    let shared_security_store = first_gateway.shared_security_store();
    let mut admission_adapters = vec![AuthenticatedIngestAdapter::new(first_gateway)];
    for (publisher, idempotency) in admission_publishers.zip(admission_idempotency) {
        let gateway = IngestGateway::with_idempotency_store(publisher, idempotency);
        let gateway = match shared_security_store.clone() {
            Some(shared) => gateway.with_shared_security_store(shared),
            None => gateway,
        };
        admission_adapters.push(AuthenticatedIngestAdapter::new(gateway));
    }
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
    let mut service = AuthenticatedGrpcService::with_pool(admission_adapters, verifier);
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
        let _idempotency_retention_worker = service.spawn_idempotency_retention_worker(
            Duration::from_secs(outbox_retention_interval_secs),
            outbox_retention_secs.saturating_mul(1000),
        );
        // Phase 0.6 item 6: early-warning backlog observability, one layer
        // above the item-5 hard capacity ceiling that already bounds outbox
        // growth (see `AuthenticatedGrpcService::spawn_backlog_monitor`'s doc
        // comment). Kept alive for the life of the server like every other
        // background worker here.
        let _backlog_monitor = service.spawn_backlog_monitor(
            Duration::from_secs(backlog_monitor_interval_secs),
            backlog_alert_depth,
            backlog_alert_age_millis,
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

#[cfg(test)]
mod effective_admission_pool_size_tests {
    use super::durability::effective_admission_pool_size;

    /// Postgres is the scale target: `open_durability_stores` passes
    /// `APEX_ADMISSION_CONCURRENCY`'s validated value straight through, so
    /// every requested pool size in the bounded 1..=32 range must survive
    /// unchanged.
    #[test]
    fn postgres_passes_the_requested_size_through_unchanged() {
        assert_eq!(effective_admission_pool_size(1, true), 1);
        assert_eq!(effective_admission_pool_size(4, true), 4);
        assert_eq!(effective_admission_pool_size(32, true), 32);
    }

    /// File/memory backends collapse to exactly one admission pool member
    /// regardless of what was requested -- N independent in-process
    /// idempotency stores would each dedup only what they personally saw,
    /// diverging from one another and defeating idempotency (see the
    /// function's doc comment and `open_durability_stores`'s).
    #[test]
    fn file_and_memory_backends_always_collapse_to_one() {
        assert_eq!(effective_admission_pool_size(1, false), 1);
        assert_eq!(effective_admission_pool_size(4, false), 1);
        assert_eq!(effective_admission_pool_size(32, false), 1);
    }
}
