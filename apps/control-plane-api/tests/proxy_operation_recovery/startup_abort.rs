//! Exercise the actual startup entry point with the sole PostgreSQL owners.
#[path = "../../src/startup/service/workers/proxy_evidence.rs"]
mod startup_entry;

use super::support::Database;
use apex_control_plane_api::{
    ControlOutboxBackend, GatewayShutdown, PostgresProxyStore, RecoveringPostgresOutbox,
};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_server::Health,
};
use tonic_health::server::{HealthReporter, HealthService};

const NAME: &str = "apex.v1.McpProxyService.EvidenceRelay";
const CHILD_MODE: &str = "APEX_PROXY_STARTUP_ABORT_CHILD";
const CHILD_URL: &str = "APEX_PROXY_STARTUP_ABORT_CHILD_URL";

#[test]
fn before_first_poll_child() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("before_first_poll") {
        return;
    }
    run_abort_child(false);
}

#[test]
fn after_healthy_idle_child() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("after_healthy_idle") {
        return;
    }
    run_abort_child(true);
}

fn run_abort_child(wait_for_healthy: bool) {
    let url = std::env::var(CHILD_URL).expect("parent must supply its owned database scope");
    // Connect outside Tokio and retain only weak references in the observer.
    let store = Arc::new(PostgresProxyStore::connect(&url).unwrap());
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&url, 100).unwrap(),
    )));
    let weak_store = Arc::downgrade(&store);
    let weak_outbox = Arc::downgrade(&outbox);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(Arc::strong_count(&outbox), 1);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let reporter = HealthReporter::new();
    let health = HealthService::from_health_reporter(reporter.clone());
    if !wait_for_healthy {
        // Also expose stale health if cancellation happens before initialization.
        // This separate future never captures either PostgreSQL owner.
        runtime.block_on(reporter.set_service_status(NAME, tonic_health::ServingStatus::Serving));
    }
    let shutdown = GatewayShutdown::default();
    runtime.block_on(async move {
        let wrapper =
            startup_entry::spawn_proxy_evidence_worker(store, outbox, reporter, shutdown.clone());
        if wait_for_healthy {
            tokio::time::timeout(Duration::from_secs(5), async {
                while named_health(&health).await != Some(ServingStatus::Serving) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("actual startup wrapper never reported healthy idle");
        }
        // On a current-thread runtime the immediate branch cannot poll the
        // wrapper before this abort. The idle branch observed real named health.
        wrapper.abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(5), wrapper)
            .await
            .expect("startup wrapper abort did not complete")
            .expect_err("startup wrapper unexpectedly completed normally");
        assert!(
            cancelled.is_cancelled(),
            "startup wrapper panicked: {cancelled}"
        );
        assert!(
            !shutdown.is_requested(),
            "abort must not request shared shutdown"
        );

        let released = tokio::time::timeout(Duration::from_secs(5), async {
            while weak_store.strong_count() != 0
                || weak_outbox.strong_count() != 0
                || named_health(&health).await != Some(ServingStatus::NotServing)
            {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "wrapper abort left store owners={}, outbox owners={}, named health={:?}",
            weak_store.strong_count(),
            weak_outbox.strong_count(),
            named_health(&health).await,
        );
        assert!(!shutdown.is_requested());
        assert_eq!(named_health(&health).await, Some(ServingStatus::NotServing));
    });
    // Runtime teardown must finish too; the parent deadline catches a detached
    // blocking relay even if assertions above panic while unwinding this child.
}

async fn named_health(health: &HealthService) -> Option<ServingStatus> {
    match health
        .check(tonic::Request::new(HealthCheckRequest {
            service: NAME.into(),
        }))
        .await
    {
        Ok(response) => Some(response.into_inner().status()),
        Err(status) if status.code() == tonic::Code::NotFound => None,
        Err(status) => panic!("named health check failed: {status}"),
    }
}

struct KillAndWait(Child);

impl Drop for KillAndWait {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn assert_abort_child(mode: &str, test: &str) {
    let database = Database::new();
    // Declare after Database so kill+wait always precedes owned-schema cleanup,
    // including timeout, wait errors, and assertion unwinding.
    let mut child = KillAndWait(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_URL, &database.url)
            .env("APEX_ALLOW_POSTGRES_PLAINTEXT", "1")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("cannot wait for startup abort child")
        {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "startup wrapper {mode} child exceeded 15s; killing and reaping it",
        );
        // Poll process completion only; readiness is actual named health above.
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "startup wrapper {mode} child failed: {status}"
    );
}

#[test]
fn startup_wrapper_abort_before_first_poll_releases_last_owners_and_clears_health() {
    assert_abort_child(
        "before_first_poll",
        "startup_abort::before_first_poll_child",
    );
}

#[test]
fn startup_wrapper_abort_after_healthy_idle_releases_last_owners_and_clears_health() {
    assert_abort_child(
        "after_healthy_idle",
        "startup_abort::after_healthy_idle_child",
    );
}
