use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use apex_control_plane_api::{
    ControlOutboxBackend, GatewayShutdown, PostgresProxyStore, ProxyEvidenceRelayStatus,
    spawn_proxy_evidence_relay,
};
use tonic_health::{ServingStatus, server::HealthReporter};

const NAME: &str = "apex.v1.McpProxyService.EvidenceRelay";

pub(crate) fn spawn_proxy_evidence_worker(
    store: Arc<PostgresProxyStore>,
    outbox: Arc<ControlOutboxBackend>,
    health: HealthReporter,
    shutdown: GatewayShutdown,
) -> tokio::task::JoinHandle<()> {
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    // Transfer every PostgreSQL owner into the cancellation-safe relay's
    // blocking job before the wrapper can capture them across an await.
    let mut relay =
        spawn_proxy_evidence_relay(store, outbox, Arc::clone(&status), shutdown.clone());
    // Capture an already-constructed guard so abort-before-first-poll also
    // stops the inner supervisor instead of detaching it.
    let stop = StopRelayOnDrop {
        relay: relay.abort_handle(),
        health: Some(health.clone()),
        runtime: tokio::runtime::Handle::current(),
    };
    tokio::spawn(async move {
        let mut stop = stop;
        health
            .set_service_status(NAME, ServingStatus::NotServing)
            .await;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let finished = loop {
            tokio::select! {
                biased;
                _ = shutdown.wait() => break false,
                _ = &mut relay => break true,
                _ = interval.tick() => {}
            }
            health
                .set_service_status(
                    NAME,
                    if status.healthy.load(Ordering::Acquire) {
                        ServingStatus::Serving
                    } else {
                        ServingStatus::NotServing
                    },
                )
                .await;
        };
        health
            .set_service_status(NAME, ServingStatus::NotServing)
            .await;
        if !finished {
            let _ = relay.await;
        }
        // Normal exit already cleared health; only cancellation needs cleanup.
        stop.health = None;
    })
}

struct StopRelayOnDrop {
    relay: tokio::task::AbortHandle,
    health: Option<HealthReporter>,
    runtime: tokio::runtime::Handle,
}

impl Drop for StopRelayOnDrop {
    fn drop(&mut self) {
        self.relay.abort();
        let Some(health) = self.health.take() else {
            return;
        };
        let runtime = self.runtime.clone();
        // Only this wrapper publishes Serving, inline, so its dropped future
        // cannot race this final NotServing with a detached health update.
        // Use one short OS-thread cleanup: Tokio may cancel newly queued async
        // or blocking jobs during teardown. This setter needs only its lock,
        // with no I/O/timers, so Handle::block_on also works after shutdown.
        // Neither the guard nor this cleanup owns any PostgreSQL resources.
        if let Err(error) = std::thread::Builder::new()
            .name("proxy-evidence-health-stop".into())
            .spawn(move || {
                runtime.block_on(health.set_service_status(NAME, ServingStatus::NotServing));
            })
        {
            eprintln!("control-plane-api: could not clear stopped proxy evidence health: {error}");
        }
    }
}
