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

#[cfg(feature = "postgres")]
mod authority;
#[cfg(feature = "postgres")]
mod browser;
mod proxy;
mod resolvers;
mod storage;
mod supervisor;
mod workers;

use proxy::{build_runtime_provider, proxy_service_status};
use resolvers::{
    build_agent_resolver, build_governance_service, build_operator_resolver, load_server_tls,
};
use storage::{build_ephemeral_store, open_inbox, open_outbox, open_proxy_store};
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
    run_until(wait_for_shutdown_signal())
}

pub(crate) fn run_until(
    signal: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority_settings = super::env::runtime_authority_env()?;
    let browser_settings = super::env::browser_env()?;
    #[cfg(not(feature = "postgres"))]
    debug_assert!(browser_settings.is_none() && authority_settings.is_none());
    let bind_addr = resolve_bind_addr()?;
    let metrics_addr = metrics_bind_addr()?;
    // Confines every configured secret path under one operator-owned
    // directory, so a compromised env var cannot point this process at
    // arbitrary files on the host. Same role as `APEX_TRUSTED_SECRET_BASE`
    // on the ingest side; a separate variable because these are separate
    // trust boundaries and, in Compose, separate mounts.
    let trusted_base = PathBuf::from(required("APEX_CONTROL_TRUSTED_SECRET_BASE")?);
    let tls = load_server_tls(&trusted_base)?;
    #[cfg(feature = "postgres")]
    let mut authority = authority::prepare(authority_settings, &trusted_base)?;
    let outbox = Arc::new(open_outbox()?);
    let inbox = Arc::new(open_inbox()?);
    let proxy_store = open_proxy_store()?;
    let proxy_root = Arc::clone(&proxy_store.backend);
    let command_retention = command_retention()?;
    let retention_millis = command_retention.as_millis().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command retention is too large",
        )
    })?;
    let resolver =
        resolvers::SharedOperatorResolver(Arc::from(build_operator_resolver(&trusted_base)?));
    #[cfg(feature = "postgres")]
    let browser_resolver = Arc::clone(&resolver.0);
    let agent_resolver = build_agent_resolver(&trusted_base)?;
    let governance_service = build_governance_service(&trusted_base)?;
    let auth = OperatorTokenAuthenticator::new(resolver.clone());
    let proxy_events = Arc::new(apex_control_plane_api::DurableProxyEventSink::new(
        Arc::clone(&outbox),
    ));
    let runtime_provider = build_runtime_provider()?;
    let mut proxy_service = McpProxyService::new(
        OperatorTokenAuthenticator::new(resolver),
        proxy_store.backend,
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
    #[cfg(feature = "postgres")]
    let mut browser =
        browser::prepare(browser_settings, &trusted_base, bind_addr, browser_resolver)?;
    #[cfg(feature = "postgres")]
    let browser_exporter = browser.as_mut().and_then(|browser| browser.exporter.take());
    #[cfg(feature = "postgres")]
    let browser_sessions = browser.as_ref().map(|browser| browser.sessions.clone());
    let metrics = GatewayRuntimeMetrics::new(fanout.is_some());
    #[cfg(feature = "postgres")]
    let metrics = match browser.as_ref() {
        Some(browser) => metrics.with_browser_observations(browser.telemetry.clone()),
        None => metrics,
    };
    let metrics = Arc::new(metrics);
    #[cfg(feature = "postgres")]
    let final_metrics = Arc::clone(&metrics);
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
    // These final owners must outlive ALL serving tasks and runtime teardown.
    // PG/NATS clients own runtimes themselves, including lazily connected NATS.
    let roots = (
        Arc::clone(&outbox),
        Arc::clone(&inbox),
        proxy_root,
        ephemeral.clone(),
        fanout.clone(),
    );
    let shutdown = GatewayShutdown::default();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    // Connect and wait only outside entered Tokio. Keep even a failed start as
    // a value so the common cleanup tail observes every partially started owner.
    #[cfg(feature = "postgres")]
    let authority_service = authority.as_mut().map(|owner| owner.start()).transpose();
    #[cfg(feature = "postgres")]
    let authority_stop = authority.as_ref();
    let stop = supervisor::StopOnDrop(shutdown.clone());
    let outcome = runtime.block_on(async move {
        #[cfg(feature = "postgres")]
        let authority_service = authority_service?;
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
        // Listener binding precedes async worker spawning. The synchronous
        // authority workers remain root-owned through any bind/TLS failure.
        let incoming = tonic::transport::server::TcpIncoming::bind(bind_addr)?;
        let server = Server::builder().tls_config(tls)?
            .add_service(health_service)
            .add_service(bounded_control_gateway_server(service))
            .add_service(bounded_mcp_proxy_service_server(proxy_service))
            .add_service(apex_control_plane_api::proto::governance_gateway_server::GovernanceGatewayServer::new(governance_service));
        #[cfg(feature = "postgres")]
        let server = server.add_optional_service(authority_service.map(
            apex_control_plane_api::bounded_runtime_authority_service_server));
        #[cfg(feature = "postgres")]
        let browser_listener = match browser.as_ref() {
            Some(browser) => Some(tokio::net::TcpListener::bind(browser.bind_addr).await?),
            None => None,
        };
        #[cfg(feature = "postgres")]
        let proxy_evidence_worker = proxy_store.operations.map(|store| {
            workers::spawn_proxy_evidence_worker(
                store, Arc::clone(&outbox), health_reporter.clone(), shutdown.clone(),
            )
        });
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
        let mut servers = tokio::task::JoinSet::new();
        let server_shutdown = shutdown.clone();
        servers.spawn(async move {
            server.serve_with_incoming_shutdown(incoming, async move { server_shutdown.wait().await; }).await
                .map_err(|_| io::Error::other("control mTLS listener failed"))
        });
        #[cfg(feature = "postgres")]
        if let (Some(browser), Some(listener)) = (browser, browser_listener) {
            // The already-bound gRPC accept loop is polled concurrently with
            // this task's bounded mTLS connection; no self-connect deadlock.
            servers.spawn(browser.serve(listener, shutdown.clone()));
        }
        let serve_result = supervisor::wait(&mut servers, signal, &shutdown).await;
        shutdown.request();
        #[cfg(feature = "postgres")]
        if let Some(owner) = authority_stop { owner.request_shutdown(); }
        health_reporter.set_service_status("apex.v1.ControlGateway", tonic_health::ServingStatus::NotServing).await;
        health_reporter.set_service_status("apex.v1.McpProxyService", tonic_health::ServingStatus::NotServing).await;
        let drain_result = supervisor::drain(&mut servers).await;
        metrics
            .shutdowns
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut worker_failed = false;
        if let Some(handle) = fanout_worker {
            worker_failed |= handle.await.is_err();
        }
        #[cfg(feature = "postgres")]
        if let Some(handle) = proxy_evidence_worker {
            worker_failed |= handle.await.is_err();
        }
        worker_failed |= inbox_retention_worker.await.is_err();
        worker_failed |= inbox_reconciliation_worker.await.is_err();
        worker_failed |= status_logger.await.is_err();
        worker_failed |= health_monitor.await.is_err();
        if let Some(handle) = metrics_server {
            worker_failed |= handle.await.is_err();
        }
        serve_result?;
        drain_result?;
        if worker_failed { return Err(io::Error::other("control background worker failed").into()); }
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    drop(stop);
    #[cfg(feature = "postgres")]
    if let Some(owner) = authority.as_ref() {
        owner.request_shutdown();
    }
    // Also runs after bind/TLS errors before the async cleanup tail was reached.
    #[cfg(feature = "postgres")]
    let session_result = runtime.block_on(async {
        match browser_sessions.as_ref() {
            Some(sessions) => sessions
                .shutdown()
                .await
                .map_err(|_| io::Error::other("browser session worker shutdown failed")),
            None => Ok(()),
        }
    });
    drop(runtime);
    #[cfg(feature = "postgres")]
    let authority_result = authority::finish(authority.as_mut());
    // The observation worker is startup-owned, never implicitly joined by an
    // async destructor. Loss/incomplete output is not an authorization result.
    #[cfg(feature = "postgres")]
    let observation_result = match browser_exporter {
        Some(exporter) => browser::observations::finish(exporter, &final_metrics),
        None => Ok(()),
    };
    #[cfg(feature = "postgres")]
    let outcome = authority::report_cleanup(outcome, authority_result, &mut std::io::stderr());
    drop(roots);
    outcome?;
    #[cfg(feature = "postgres")]
    session_result?;
    #[cfg(feature = "postgres")]
    observation_result?;
    Ok(())
}
