//! Process wiring for the OOB control gateway: bind policy, TLS identity,
//! durable outbox, operator credential table, and the tonic server.
//!
//! Structurally the mirror of `apps/event-ingest/src/startup/service.rs`, and
//! deliberately so -- this service must not ship a weaker transport boundary
//! than the ingest gateway sitting next to it.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use apex_control_plane_api::{
    ControlGatewayService, GatewayRuntimeMetrics, GatewayShutdown, McpProxyService,
    OperatorTokenAuthenticator, bounded_control_gateway_server, bounded_mcp_proxy_service_server,
};
use tonic::transport::Server;

use super::env::{
    admission_limits, command_retention, metrics_bind_addr, required, resolve_bind_addr,
};
use super::fanout::prepare_control_fanout;

mod resolvers;
mod storage;
mod proxy;
mod workers;

use resolvers::{
    build_agent_resolver, build_governance_service, build_operator_resolver, load_server_tls,
};
use storage::{build_ephemeral_store, open_inbox, open_outbox, open_proxy_store};
use proxy::{build_runtime_provider, proxy_service_status};
use workers::{
    spawn_health_monitor, spawn_inbox_reconciliation_worker, spawn_inbox_retention_worker,
    spawn_metrics_server, spawn_status_logger, wait_for_shutdown_signal,
};

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
    let proxy_store = open_proxy_store()?;
    let command_retention = command_retention()?;
    let retention_millis = command_retention.as_millis().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command retention is too large",
        )
    })?;
    let resolver = build_operator_resolver(&trusted_base)?;
    let proxy_resolver = build_operator_resolver(&trusted_base)?;
    let agent_resolver = build_agent_resolver(&trusted_base)?;
    let governance_service = build_governance_service(&trusted_base)?;
    let auth = OperatorTokenAuthenticator::new(resolver);
    let proxy_events = Arc::new(apex_control_plane_api::DurableProxyEventSink::new(
        Arc::clone(&outbox),
    ));
    let runtime_provider = build_runtime_provider()?;
    let mut proxy_service = McpProxyService::new(
        OperatorTokenAuthenticator::new(proxy_resolver),
        proxy_store,
    )
    .with_event_sink(proxy_events);
    let proxy_is_serving = runtime_provider.is_some();
    if let Some(runtime_provider) = runtime_provider {
        proxy_service = proxy_service.with_runtime_provider(runtime_provider);
    }
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
                "apex.v1.McpProxyService",
                proxy_service_status(true, proxy_is_serving),
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
        health_reporter
            .set_service_status(
                "apex.v1.GovernanceGateway",
                tonic_health::ServingStatus::Serving,
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
            fanout.spawn(Arc::clone(&outbox), Arc::clone(&metrics), shutdown.clone())
        });
        let inbox_retention_worker = spawn_inbox_retention_worker(
            Arc::clone(&outbox),
            Arc::clone(&inbox),
            retention_millis,
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        let inbox_reconciliation_worker = spawn_inbox_reconciliation_worker(
            Arc::clone(&outbox),
            Arc::clone(&inbox),
            retention_millis,
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        let status_logger = spawn_status_logger(
            Arc::clone(&outbox),
            Arc::clone(&inbox),
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
        let metrics_server = metrics_addr
            .map(|addr| spawn_metrics_server(addr, Arc::clone(&metrics), shutdown.clone()));
        println!(
            "apex-control-plane-api listening on {bind_addr} (mTLS, client certificate required)"
        );
        let signal_shutdown = shutdown.clone();
        let signal_reporter = health_reporter.clone();
        let serve_result = Server::builder()
            .tls_config(tls)?
            .add_service(health_service)
            .add_service(bounded_control_gateway_server(service))
            .add_service(bounded_mcp_proxy_service_server(proxy_service))
            .add_service(
                apex_control_plane_api::proto::governance_gateway_server::GovernanceGatewayServer::new(
                    governance_service,
                ),
            )
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
