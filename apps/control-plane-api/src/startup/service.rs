//! Process wiring for the OOB control gateway: bind policy, TLS identity,
//! durable outbox, operator credential table, and the tonic server.
//!
//! Structurally the mirror of `apps/event-ingest/src/startup/service.rs`, and
//! deliberately so -- this service must not ship a weaker transport boundary
//! than the ingest gateway sitting next to it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apex_control_plane_api::{
    BoxedAgentWorkloadResolver, BoxedOperatorCredentialResolver, ControlGatewayService,
    ControlInboxBackend, ControlOutboxBackend, FileCommandInbox, GatewayRuntimeMetrics,
    GatewayShutdown,
    KeycloakConfig,
    KeycloakOperatorCredentialResolver, OperatorTokenAuthenticator, SharedEphemeralStore,
    StaticAgentWorkloadResolver, bounded_control_gateway_server, parse_agent_token_table,
    parse_operator_token_table,
};
#[cfg(feature = "postgres")]
use apex_control_plane_api::{RecoveringPostgresCommandInbox, RecoveringPostgresOutbox};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::env::{
    AgentTokenSource, OperatorTokenSource, admission_limits, agent_token_source,
    command_retention, control_postgres_url, control_valkey_env, keycloak_env,
    metrics_bind_addr, operator_token_source, path, postgres_pool_size, required,
    resolve_bind_addr,
};
use super::fanout::prepare_control_fanout;
use super::secrets::{read_bounded, read_credential_table, trusted_secret_path};

/// PEM material ceiling, matching `event-ingest`'s own 1 MiB bound on the
/// same three files.
const MAX_TLS_MATERIAL_BYTES: usize = 1024 * 1024;
/// The credential table is `token|scopes;...` with up to 256 entries of up to
/// 4096 token bytes (`auth::MAX_OPERATOR_TOKEN_ENTRIES` /
/// `MAX_OPERATOR_TOKEN_BYTES`), so 64 KiB is generous headroom while still
/// bounding what a mounted file can make this process allocate.
const MAX_OPERATOR_TABLE_BYTES: usize = 64 * 1024;
const OUTBOX_CAPACITY: usize = 1_000_000;
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INBOX_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const INBOX_RECONCILIATION_BATCH: usize = 256;

/// Loads the mTLS server identity and the CA that operator client
/// certificates must chain to.
///
/// **TLS is mandatory.** All three paths are `required()`, so a missing one
/// aborts startup instead of silently degrading to plaintext. This matches
/// `event-ingest` exactly: that binary has no "lab mode" TLS bypass either --
/// `APEX_GATEWAY_SERVER_CERT_FILE`/`_KEY_FILE`/`_CLIENT_CA_FILE` are all
/// `path()` (i.e. required) and its `client_auth_optional(false)` is
/// explicit. Local and CI use is served by the real PKI in
/// `deploy/compose/live-mtls/`, not by an unencrypted fallback, so adding one
/// here would invent a weaker mode that does not exist anywhere else in this
/// repository.
fn load_server_tls(trusted_base: &Path) -> Result<ServerTlsConfig, io::Error> {
    let server_cert_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_CERT_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_KEY_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        true,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca_path = trusted_secret_path(
        &path("APEX_CONTROL_CLIENT_CA_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    let server_cert = read_bounded(
        &server_cert_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key = read_bounded(
        &server_key_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca = read_bounded(
        &client_ca_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca))
        // Explicit, for the same reason `event-ingest` states it explicitly:
        // a tonic upgrade must not be able to make operator client
        // certificates optional at the gRPC boundary by changing a default.
        .client_auth_optional(false))
}

/// PEM ceiling for the Keycloak JWKS CA, matching the mTLS material bound.
const MAX_KEYCLOAK_CA_BYTES: usize = 1024 * 1024;

/// Selects the operator credential verifier.
///
/// Three paths, chosen by explicit configuration and never inferred from one
/// another (see [`super::env::operator_token_source_value`]):
///
/// - **Keycloak** (`APEX_CONTROL_KEYCLOAK_ISSUER`) -- the production path.
///   Verifies short-lived, scope-bound credentials Keycloak issued through
///   RFC 8693 token exchange. This process is a resource server: it holds no
///   client secret, performs no exchange, and only checks signatures and
///   claims.
/// - **File** (`APEX_CONTROL_OPERATOR_TOKENS_FILE`) and **inline**
///   (`APEX_CONTROL_OPERATOR_TOKENS`) -- the static table, unchanged, still
///   the local/lab and CI seam.
///
/// The return type is erased because the three implementations are different
/// types; `ControlGatewayService` stays generic so in-process tests keep
/// monomorphising over the resolver they actually construct.
fn build_operator_resolver(
    trusted_base: &Path,
) -> Result<BoxedOperatorCredentialResolver, Box<dyn std::error::Error>> {
    let raw = match operator_token_source()? {
        OperatorTokenSource::Keycloak(issuer) => {
            let settings = keycloak_env(issuer)?;
            let ca_path = trusted_secret_path(
                &settings.ca_file,
                trusted_base,
                MAX_KEYCLOAK_CA_BYTES as u64,
                // A CA certificate is public material, so it is not held to
                // the private-key permission policy -- the same call the
                // NATS/mTLS client CAs get.
                false,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let jwks_ca_pem = read_bounded(
                &ca_path,
                MAX_KEYCLOAK_CA_BYTES,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let config = KeycloakConfig {
                issuer: settings.issuer,
                audience: settings.audience,
                jwks_url: settings.jwks_url,
                jwks_ca_pem,
                jwks_refresh: settings.jwks_refresh,
                jwks_max_age: settings.jwks_max_age,
                scope_claim: settings.scope_claim,
                role_claim: settings.role_claim,
                global_role: settings.global_role,
                global_subjects: settings.global_subjects,
                max_token_lifetime: settings.max_token_lifetime,
                expected_typ: settings.expected_typ,
            };
            let break_glass = if config.global_role.is_some() {
                config.global_subjects.len()
            } else {
                0
            };
            // Constructed here, before the serving runtime exists: the JWKS
            // client is `reqwest::blocking` and owns an internal runtime, so
            // building it on a runtime thread panics -- the same hazard that
            // made `run()` synchronous for `PostgresOutbox`.
            let resolver = KeycloakOperatorCredentialResolver::start(config)?;
            println!(
                "apex-control-plane-api operator credentials: keycloak (break-glass subjects allow-listed: {break_glass})"
            );
            return Ok(Box::new(resolver));
        }
        OperatorTokenSource::File(configured) => {
            let table_path = trusted_secret_path(
                &configured,
                trusted_base,
                MAX_OPERATOR_TABLE_BYTES as u64,
                // Bearer credentials, not just a config file: held to the
                // same owner-only permission policy as a private key.
                true,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?;
            read_credential_table(
                &table_path,
                MAX_OPERATOR_TABLE_BYTES,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?
        }
        OperatorTokenSource::Inline(raw) => raw,
        OperatorTokenSource::Unset => {
            // Fail-closed, not fail-open: an empty resolver authenticates
            // nobody. Loud on stderr because a control gateway that accepts
            // no operator at all is almost never what was intended.
            eprintln!(
                "control-plane-api: none of APEX_CONTROL_KEYCLOAK_ISSUER, APEX_CONTROL_OPERATOR_TOKENS_FILE or APEX_CONTROL_OPERATOR_TOKENS is set; no operator credential will authenticate"
            );
            return Ok(Box::new(
                apex_control_plane_api::StaticOperatorTokenResolver::new(),
            ));
        }
    };
    // A malformed credential table is a configuration failure, not something
    // to log past. Skipping a bad entry would leave the gateway running with
    // an operator silently unable to act -- or, worse, acting under a
    // mis-parsed scope.
    let resolver = parse_operator_token_table(&raw)?;
    println!("apex-control-plane-api operator credentials: static table");
    Ok(Box::new(resolver))
}

/// The agent workload credential table is the same shape and the same size
/// class as the operator one: `token|cert_sha256|agent_id|scopes`, up to 1024
/// entries.
const MAX_AGENT_TABLE_BYTES: usize = 256 * 1024;

/// Selects the **agent workload** credential verifier for `PollCommands`.
///
/// Deliberately its own function, its own variables, and its own fail-closed
/// default, rather than a branch inside `build_operator_resolver`. Sharing that
/// function would be the first step toward sharing the credential space, which
/// is the boundary ADR-0006 draws between issuing a command and receiving one.
///
/// Unset is a *supported* configuration: a deployment that has not yet issued
/// agent workload credentials still runs a perfectly good command gateway, it
/// simply has no agent that can retrieve them. It is announced loudly on
/// stderr, because a control channel where nothing can receive a `stop` is the
/// exact situation this work item exists to make visible rather than silent.
fn build_agent_resolver(
    trusted_base: &Path,
) -> Result<BoxedAgentWorkloadResolver, Box<dyn std::error::Error>> {
    let raw = match agent_token_source()? {
        AgentTokenSource::File(configured) => {
            let table_path = trusted_secret_path(
                &configured,
                trusted_base,
                MAX_AGENT_TABLE_BYTES as u64,
                // Bearer credentials, held to the same owner-only permission
                // policy as a private key and as the operator table.
                true,
                "APEX_CONTROL_AGENT_TOKENS_FILE",
            )?;
            read_credential_table(
                &table_path,
                MAX_AGENT_TABLE_BYTES,
                "APEX_CONTROL_AGENT_TOKENS_FILE",
            )?
        }
        AgentTokenSource::Inline(raw) => raw,
        AgentTokenSource::Unset => {
            eprintln!(
                "control-plane-api: neither APEX_CONTROL_AGENT_TOKENS_FILE nor APEX_CONTROL_AGENT_TOKENS is set; no agent will be able to retrieve commands through PollCommands"
            );
            println!("apex-control-plane-api agent credentials: none configured");
            return Ok(BoxedAgentWorkloadResolver::new(
                StaticAgentWorkloadResolver::new(),
            ));
        }
    };
    let resolver = parse_agent_token_table(&raw)?;
    println!("apex-control-plane-api agent credentials: static table");
    Ok(BoxedAgentWorkloadResolver::new(resolver))
}

/// Opens the durable command inbox -- the delivery-state store `PollCommands`
/// reads and the accept path writes. It follows the outbox backend selection:
/// a Postgres outbox gets a Postgres inbox, so every replica sees the same
/// delivery state; otherwise both remain on the operator-owned file volume.
fn open_inbox() -> Result<ControlInboxBackend, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Some(url) = control_postgres_url()? {
            let pool_size = postgres_pool_size()?;
            let mut inboxes = Vec::with_capacity(pool_size);
            for _ in 0..pool_size {
                let inbox = RecoveringPostgresCommandInbox::connect(&url, OUTBOX_CAPACITY)
                    .map_err(|error| format!("failed to open control inbox: {}", error.code.as_str()))?;
                inboxes.push(Box::new(inbox) as Box<dyn apex_control_plane_api::CommandInbox + Send>);
            }
            println!("apex-control-plane-api inbox backend: postgres");
            return ControlInboxBackend::new_pool(inboxes)
                .map_err(|_| io::Error::other("failed to create control inbox pool").into());
        }
    }
    let base = inbox_base();
    std::fs::create_dir_all(&base)?;
    let inbox_file = base.join(
        std::env::var("APEX_CONTROL_INBOX_FILE").unwrap_or_else(|_| "inbox.jsonl".to_owned()),
    );
    let inbox = FileCommandInbox::open(&inbox_file, &base, OUTBOX_CAPACITY)
        .map_err(|error| format!("failed to open control inbox: {}", error.code.as_str()))?;
    println!("apex-control-plane-api inbox backend: file");
    Ok(ControlInboxBackend::new(Box::new(inbox)))
}

/// Where the file outbox lives.
fn outbox_base() -> PathBuf {
    PathBuf::from(
        std::env::var("APEX_CONTROL_OUTBOX_BASE")
            .unwrap_or_else(|_| "./data/control-outbox".to_owned()),
    )
}

/// Where the command inbox lives.
///
/// Defaults to the outbox base, because for a file-backed deployment they are
/// the same durability volume and splitting them by default would be a way to
/// lose one of them. It remains separately configurable for deployments that
/// intentionally choose a local file inbox.
fn inbox_base() -> PathBuf {
    match std::env::var("APEX_CONTROL_INBOX_BASE") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => outbox_base(),
    }
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut terminate) = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Periodically removes settled delivery state while retaining command
/// identities for the configured idempotency window. This runs independently
/// of JetStream so a broker outage cannot make the local inbox grow forever.
fn spawn_inbox_retention_worker(
    outbox: Arc<ControlOutboxBackend>,
    inbox: Arc<ControlInboxBackend>,
    retention_millis: u64,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let outbox = Arc::clone(&outbox);
            let inbox = Arc::clone(&inbox);
            let metrics = Arc::clone(&metrics);
            let _ = tokio::task::spawn_blocking(move || {
                let now = now_unix_millis();
                let inbox_failed = inbox
                    .with_lock(|store| {
                        store.maintain(
                            now,
                            retention_millis,
                            apex_control_plane_api::DEFAULT_MAX_DELIVERY_ATTEMPTS,
                        )
                    })
                    .map_or(true, |result| result.is_err());
                // Expire the inbox tombstone first. If a process dies between
                // these two operations, a reused command_id still gets a
                // deliverable inbox record attached to the existing audit
                // event rather than an outbox row with no agent delivery.
                let outbox_failed = outbox.maintain(now, retention_millis).is_err();
                if outbox_failed || inbox_failed {
                    metrics
                        .retention_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
            .await;
        }
    })
}

/// Repairs the only non-atomic boundary left by the intentionally separate
/// outbox and inbox stores: a process can die after the authoritative outbox
/// commit but before the delivery record. Pending control events are decoded
/// back into their delivery shape and recorded idempotently. This is harmless
/// for normal submissions and closes the retry-after-timeout dependency.
fn spawn_inbox_reconciliation_worker(
    outbox: Arc<ControlOutboxBackend>,
    inbox: Arc<ControlInboxBackend>,
    retention_millis: u64,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(INBOX_RECONCILIATION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let outbox = Arc::clone(&outbox);
            let inbox = Arc::clone(&inbox);
            let metrics = Arc::clone(&metrics);
            let _ = tokio::task::spawn_blocking(move || {
                let now = now_unix_millis();
                let since = now.saturating_sub(retention_millis);
                let Ok(mut events) = outbox.pending_reconciliation_batch(
                    INBOX_RECONCILIATION_BATCH,
                ) else {
                    metrics
                        .reconciliation_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("control-plane-api: inbox reconciliation could not read the outbox");
                    return;
                };
                let Ok(completed) = outbox.recent_completed_batch(
                    since,
                    INBOX_RECONCILIATION_BATCH,
                ) else {
                    metrics
                        .reconciliation_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "control-plane-api: completed-row reconciliation could not read the outbox"
                    );
                    return;
                };
                events.extend(completed);
                for event in events {
                    let Ok(delivery) = apex_control_plane_api::pending_command_from_ingest_request(
                        &event,
                    ) else {
                        metrics
                            .reconciliation_failures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        eprintln!(
                            "control-plane-api: inbox reconciliation skipped a malformed control event"
                        );
                        continue;
                    };
                    let result = inbox.with_lock(|store| store.record(&delivery));
                    match result {
                        Ok(Ok(apex_control_plane_api::RecordResult::Recorded)) => {
                            metrics
                                .reconciliation_repairs
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(Ok(apex_control_plane_api::RecordResult::AlreadyRecorded)) => {}
                        Ok(Err(_)) | Err(_) => {
                            metrics
                                .reconciliation_failures
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            eprintln!(
                                "control-plane-api: inbox reconciliation could not record a pending command"
                            );
                        }
                    }
                }
            })
            .await;
        }
    })
}

fn spawn_status_logger(
    outbox: Arc<ControlOutboxBackend>,
    metrics: Arc<GatewayRuntimeMetrics>,
    ephemeral: Option<SharedEphemeralStore>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => break,
            }
            let accelerator_sidelined = ephemeral.as_ref().is_some_and(|store| {
                store
                    .lock()
                    .map(|guard| guard.accelerator_sidelined())
                    .unwrap_or(true)
            });
            if let Ok(count) = outbox.quarantined_count() {
                metrics
                    .quarantined_current
                    .store(count, std::sync::atomic::Ordering::Relaxed);
            }
            eprintln!("{}", metrics.status_line(accelerator_sidelined));
        }
    })
}

fn spawn_health_monitor(
    reporter: tonic_health::server::HealthReporter,
    metrics: Arc<GatewayRuntimeMetrics>,
    ephemeral: Option<SharedEphemeralStore>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.wait() => {
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway.Fanout",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    reporter
                        .set_service_status(
                            "apex.v1.ControlGateway.AdmissionAccelerator",
                            tonic_health::ServingStatus::NotServing,
                        )
                        .await;
                    break;
                }
            }
            let accelerator_sidelined = ephemeral.as_ref().is_some_and(|store| {
                store
                    .lock()
                    .map(|guard| guard.accelerator_sidelined())
                    .unwrap_or(true)
            });
            metrics.set_accelerator_sidelined(accelerator_sidelined);
            let storage_status = if metrics
                .storage_healthy
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            let fanout_status = if metrics
                .fanout_healthy
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            let accelerator_status = if metrics.accelerator_healthy() {
                tonic_health::ServingStatus::Serving
            } else {
                tonic_health::ServingStatus::NotServing
            };
            reporter
                .set_service_status("apex.v1.ControlGateway", storage_status)
                .await;
            reporter
                .set_service_status("apex.v1.ControlGateway.Fanout", fanout_status)
                .await;
            reporter
                .set_service_status(
                    "apex.v1.ControlGateway.AdmissionAccelerator",
                    accelerator_status,
                )
                .await;
        }
    })
}

/// Serves a loopback-only Prometheus text endpoint without adding an HTTP
/// framework to the control plane. It is intentionally separate from the
/// mTLS command listener: metrics are local diagnostics, never a remote
/// control surface.
fn spawn_metrics_server(
    addr: std::net::SocketAddr,
    metrics: Arc<GatewayRuntimeMetrics>,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("apex-control-plane-api: metrics listener failed: {error}");
                return;
            }
        };
        eprintln!("apex-control-plane-api metrics listening on http://{addr}/metrics");
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue; };
                    let metrics = Arc::clone(&metrics);
                    tokio::spawn(async move {
                        serve_metrics_connection(stream, metrics).await;
                    });
                }
            }
        }
    })
}

async fn serve_metrics_connection(
    mut stream: tokio::net::TcpStream,
    metrics: Arc<GatewayRuntimeMetrics>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut request = [0_u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(0);
    let first_line = String::from_utf8_lossy(&request[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let snapshot = metrics.snapshot();
    let (status, body) = if first_line.starts_with("GET /metrics ") {
        (
            "200 OK",
            format!(
                "# TYPE apex_control_gateway_submissions_total counter\napex_control_gateway_submissions_total {}\n# TYPE apex_control_gateway_duplicate_submissions_total counter\napex_control_gateway_duplicate_submissions_total {}\n# TYPE apex_control_gateway_polls_total counter\napex_control_gateway_polls_total {}\n# TYPE apex_control_gateway_fanout_successes_total counter\napex_control_gateway_fanout_successes_total {}\n# TYPE apex_control_gateway_fanout_failures_total counter\napex_control_gateway_fanout_failures_total {}\n# TYPE apex_control_gateway_quarantined_rows_total counter\napex_control_gateway_quarantined_rows_total {}\n# TYPE apex_control_gateway_quarantined_rows gauge\napex_control_gateway_quarantined_rows {}\n# TYPE apex_control_gateway_storage_healthy gauge\napex_control_gateway_storage_healthy {}\n# TYPE apex_control_gateway_fanout_healthy gauge\napex_control_gateway_fanout_healthy {}\n# TYPE apex_control_gateway_accelerator_configured gauge\napex_control_gateway_accelerator_configured {}\n# TYPE apex_control_gateway_accelerator_sidelined gauge\napex_control_gateway_accelerator_sidelined {}\n",
                snapshot.submissions,
                snapshot.duplicate_submissions,
                snapshot.polls,
                snapshot.fanout_successes,
                snapshot.fanout_failures,
                snapshot.quarantined_rows,
                snapshot.quarantined_current,
                u8::from(snapshot.storage_healthy),
                u8::from(snapshot.fanout_healthy),
                u8::from(snapshot.accelerator_configured),
                u8::from(snapshot.accelerator_sidelined),
            ),
        )
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

/// Builds the optional cross-replica admission accelerator.
///
/// Structurally `event-ingest`'s `build_ephemeral_store`, with one deliberate
/// difference: an unreachable Valkey **does not stop this gateway starting**.
///
/// `event-ingest` refuses to come up if `ValkeyEphemeralStore::connect` fails,
/// which is defensible for the ingest data path. Doing the same here would
/// make an explicitly non-authoritative accelerator a hard startup dependency
/// of the out-of-band control channel -- the exact coupling ADR-0006 exists to
/// remove, and the same mistake the JetStream publisher already had to avoid.
/// So the split is the same one used there: **configuration errors abort
/// startup loudly, an unreachable instance does not.** A refused *config*
/// (`EphemeralErrorCode::InvalidKey` -- a path outside the trusted base, a
/// key readable beyond its owner, a malformed host) is a misconfiguration;
/// `Unavailable` is an outage, and an outage means the process runs on its
/// process-local ceiling, which is the hard floor either way.
///
/// The connection is also re-established lazily by [`LazyValkeyStore`] rather
/// than only at startup, so a Valkey that was down when this process booted is
/// picked up without a restart -- and `FallbackEphemeralStore`'s circuit
/// breaker is what keeps that retry from becoming a per-request stall.
fn build_ephemeral_store(
    trusted_base: &Path,
) -> Result<Option<SharedEphemeralStore>, Box<dyn std::error::Error>> {
    let configured = control_valkey_env()?;
    #[cfg(feature = "valkey")]
    {
        use apex_event_ingest::{EphemeralStore, FallbackEphemeralStore, InMemoryEphemeralStore};

        if let Some(settings) = configured {
            let config = apex_event_ingest::ValkeyConfig {
                host: settings.host,
                port: settings.port,
                username: settings.username,
                password_file: settings.password_file,
                ca_file: settings.ca_file,
                client_cert_file: settings.client_cert_file,
                client_key_file: settings.client_key_file,
                trusted_base: trusted_base.to_path_buf(),
            };
            // Eager *configuration* validation, deferred connection. Same
            // split as `NatsTlsConfig::validate` in `startup/fanout.rs`, and
            // for the same reason.
            config.validate().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "APEX_CONTROL_VALKEY_* configuration was refused: {}",
                        error.code.as_str()
                    ),
                )
            })?;
            let store: Box<dyn EphemeralStore> = Box::new(FallbackEphemeralStore::new(
                super::valkey::LazyValkeyStore::new(config),
                InMemoryEphemeralStore::new(),
            ));
            println!(
                "apex-control-plane-api admission ceiling: shared (valkey), local ceiling retained as the floor"
            );
            return Ok(Some(std::sync::Mutex::new(store).into()));
        }
    }
    #[cfg(not(feature = "valkey"))]
    {
        let _ = trusted_base;
        if configured.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_VALKEY_HOST is set but this binary was not built with --features valkey",
            )
            .into());
        }
    }
    println!("apex-control-plane-api admission ceiling: process-local only");
    Ok(None)
}

/// Selects the durable outbox backend, mirroring `event-ingest`'s
/// `open_durability_stores`: a URL selects Postgres, its absence selects the
/// file backend, and a URL set on a binary built without `--features postgres`
/// is a hard startup error rather than a silent downgrade to a single-writer
/// file.
///
/// That last case is the one this function used to get wrong in the other
/// direction. It unconditionally built a `FileOutbox`, so `--features postgres`
/// changed nothing about the running binary -- it only forwarded the feature to
/// `apex-event-ingest`. A deployment that believed it had a multi-writer
/// backend had a single-writer one, which is exactly the assumption
/// cross-replica work would have been built on top of.
fn open_outbox() -> Result<ControlOutboxBackend, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Some(url) = control_postgres_url()? {
            // Reused verbatim from `event-ingest`, including its multi-replica
            // fixes (advisory-locked schema DDL, `ON CONFLICT DO NOTHING` on
            // the insert race, and `FOR UPDATE SKIP LOCKED` claim leases in
            // `pending_batch()`). See `env::control_postgres_url_value` for why this
            // must be a different database or schema from the ingest
            // gateway's, given both share the `apex_event_outbox` table name.
            let pool_size = postgres_pool_size()?;
            let mut outboxes = Vec::with_capacity(pool_size);
            for _ in 0..pool_size {
                let outbox = RecoveringPostgresOutbox::connect(&url, OUTBOX_CAPACITY)
                    .map_err(|error| {
                        format!("failed to open control outbox: {}", error.code.as_str())
                    })?;
                outboxes.push(Box::new(outbox) as Box<dyn apex_event_ingest::EventOutbox + Send>);
            }
            println!("apex-control-plane-api outbox backend: postgres");
            println!("apex-control-plane-api postgres outbox pool: {pool_size} connection(s)");
            return ControlOutboxBackend::new_pool(outboxes)
                .map_err(|_| io::Error::other("failed to create control outbox pool").into());
        }
    }
    #[cfg(not(feature = "postgres"))]
    {
        if control_postgres_url()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_POSTGRES_URL is set but this binary was not built with --features postgres",
            )
            .into());
        }
    }
    let outbox_base = outbox_base();
    std::fs::create_dir_all(&outbox_base)?;
    let outbox_file = outbox_base.join(
        std::env::var("APEX_CONTROL_OUTBOX_FILE").unwrap_or_else(|_| "commands.jsonl".to_owned()),
    );
    let file_outbox =
        apex_event_ingest::FileOutbox::open(&outbox_file, &outbox_base, OUTBOX_CAPACITY)
            .map_err(|error| format!("failed to open control outbox: {}", error.code.as_str()))?;
    println!("apex-control-plane-api outbox backend: file");
    Ok(ControlOutboxBackend::new(Box::new(file_outbox)))
}

/// Synchronous by design, exactly as `apps/event-ingest/src/startup/service.rs`
/// is and for the same reason: some clients constructed below own an internal
/// tokio runtime and `block_on` it during construction, which **panics** on a
/// thread that already has a runtime entered.
///
/// This is not hypothetical. `run()` was `async` under `#[tokio::main]` until
/// the Postgres backend was wired in, at which point
/// `PostgresOutbox::connect` -> `postgres::Config::connect` panicked with
/// "Cannot start a runtime from within a runtime" on the first real container
/// start -- while every in-process test stayed green, because none of them
/// construct a blocking client inside an async `run()`. The runtime this
/// process serves on is therefore created at the end, once construction is
/// complete.
pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = resolve_bind_addr()?;
    let metrics_addr = metrics_bind_addr()?;
    // Confines every configured secret path under one operator-owned
    // directory, so a compromised env var cannot point this process at
    // arbitrary files on the host. Same role as `APEX_TRUSTED_SECRET_BASE`
    // on the ingest side; a separate variable because these are separate
    // trust boundaries and, in Compose, separate mounts.
    let trusted_base = PathBuf::from(required("APEX_CONTROL_TRUSTED_SECRET_BASE")?);
    let tls = load_server_tls(&trusted_base)?;
    let outbox = Arc::new(open_outbox()?);
    let inbox = Arc::new(open_inbox()?);
    let command_retention = command_retention()?;
    let retention_millis = command_retention
        .as_millis()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "command retention is too large"))?;
    let resolver = build_operator_resolver(&trusted_base)?;
    let agent_resolver = build_agent_resolver(&trusted_base)?;
    let auth = OperatorTokenAuthenticator::new(resolver);
    // Resolved and validated here, with no runtime entered; spawned below,
    // inside one. No socket is opened either way -- an unreachable broker
    // must never stop this gateway from starting (ADR-0006).
    let fanout = prepare_control_fanout(&trusted_base)?;
    let (admission_limit, admission_window) = admission_limits()?;
    // Built here, with no runtime entered: `ValkeyEphemeralStore::connect`
    // is synchronous and the wrapper around it must not be constructed on a
    // runtime thread any more than the Postgres client may be.
    let ephemeral = build_ephemeral_store(&trusted_base)?;
    let metrics = Arc::new(GatewayRuntimeMetrics::new(fanout.is_some()));
    metrics.set_accelerator_configured(ephemeral.is_some());
    let mut service =
        ControlGatewayService::with_inbox(auth, Arc::clone(&outbox), Arc::clone(&inbox))
            .with_agent_resolver(agent_resolver)
            .with_admission_limits(admission_limit, admission_window)
            .with_metrics(Arc::clone(&metrics));
    if let Some(store) = ephemeral.clone() {
        service = service.with_ephemeral_store(store);
    }
    println!(
        "apex-control-plane-api admission limit: {admission_limit} command(s) per operator per {}s",
        admission_window.as_secs()
    );
    println!(
        "apex-control-plane-api command retention: {}d",
        command_retention.as_secs() / (24 * 60 * 60)
    );

    // Everything above is built without a runtime entered. Same comment, same
    // reason, as `event-ingest`'s own `run()`.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_service_status(
                "apex.v1.ControlGateway",
                tonic_health::ServingStatus::Serving,
            )
            .await;
        health_reporter
            .set_service_status(
                "apex.v1.ControlGateway.Fanout",
                if fanout.is_some() {
                    tonic_health::ServingStatus::Serving
                } else {
                    tonic_health::ServingStatus::NotServing
                },
            )
            .await;
        health_reporter
            .set_service_status(
                "apex.v1.ControlGateway.AdmissionAccelerator",
                if metrics.accelerator_healthy() {
                    tonic_health::ServingStatus::Serving
                } else {
                    tonic_health::ServingStatus::NotServing
                },
            )
            .await;
        let shutdown = GatewayShutdown::default();
        // Bound to a named variable, not `_`, and kept alive until `serve`
        // returns: this is the only thing that turns a durably accepted
        // command into an observable `control` event. Nothing on the accept
        // path touches it -- `ControlGatewayService` never sees the publisher
        // -- so a JetStream outage delays `delivered` and defers the trace
        // write without affecting whether a command is accepted (ADR-0006).
        let fanout_worker = fanout.map(|fanout| {
            fanout.spawn(
                Arc::clone(&outbox),
                Arc::clone(&metrics),
                shutdown.clone(),
            )
        });
        let inbox_retention_worker =
            spawn_inbox_retention_worker(
                Arc::clone(&outbox),
                Arc::clone(&inbox),
                retention_millis,
                Arc::clone(&metrics),
                shutdown.clone(),
            );
        let inbox_reconciliation_worker =
            spawn_inbox_reconciliation_worker(
                Arc::clone(&outbox),
                Arc::clone(&inbox),
                retention_millis,
                Arc::clone(&metrics),
                shutdown.clone(),
            );
        let status_logger = spawn_status_logger(
            Arc::clone(&outbox),
            Arc::clone(&metrics),
            ephemeral.clone(),
            shutdown.clone(),
        );
        let health_monitor = spawn_health_monitor(
            health_reporter.clone(),
            Arc::clone(&metrics),
            ephemeral.clone(),
            shutdown.clone(),
        );
        let metrics_server = metrics_addr.map(|addr| {
            spawn_metrics_server(addr, Arc::clone(&metrics), shutdown.clone())
        });
        println!(
            "apex-control-plane-api listening on {bind_addr} (mTLS, client certificate required)"
        );
        let signal_shutdown = shutdown.clone();
        let signal_reporter = health_reporter.clone();
        let serve_result = Server::builder()
            .tls_config(tls)?
            .add_service(health_service)
            .add_service(bounded_control_gateway_server(service))
            .serve_with_shutdown(bind_addr, async move {
                wait_for_shutdown_signal().await;
                signal_reporter
                    .set_service_status(
                        "apex.v1.ControlGateway",
                        tonic_health::ServingStatus::NotServing,
                    )
                    .await;
                signal_shutdown.request();
            })
            .await;
        shutdown.request();
        metrics
            .shutdowns
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = fanout_worker {
            let _ = handle.await;
        }
        let _ = inbox_retention_worker.await;
        let _ = inbox_reconciliation_worker.await;
        let _ = status_logger.await;
        let _ = health_monitor.await;
        if let Some(handle) = metrics_server {
            let _ = handle.await;
        }
        serve_result?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
