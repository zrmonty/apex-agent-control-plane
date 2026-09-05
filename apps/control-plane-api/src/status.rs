use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::Notify;

#[cfg(feature = "postgres")]
mod browser;

#[derive(Clone, Debug, Default)]
pub struct GatewayShutdown {
    requested: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl GatewayShutdown {
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        if self.is_requested() {
            return;
        }
        notified.await;
    }
}

/// Low-cardinality runtime counters emitted by the gateway's periodic status
/// line. They are deliberately independent of a metrics dependency so the
/// control channel keeps its small, failure-tolerant dependency surface.
#[derive(Debug)]
pub struct GatewayRuntimeMetrics {
    #[cfg(feature = "postgres")]
    browser: Option<browser::BrowserObservations>,
    pub submissions: AtomicU64,
    pub duplicate_submissions: AtomicU64,
    pub polls: AtomicU64,
    pub fanout_successes: AtomicU64,
    pub fanout_failures: AtomicU64,
    pub retention_failures: AtomicU64,
    pub reconciliation_repairs: AtomicU64,
    pub reconciliation_failures: AtomicU64,
    pub outbox_read_failures: AtomicU64,
    pub outbox_write_failures: AtomicU64,
    pub quarantined_rows: AtomicU64,
    pub quarantined_current: AtomicU64,
    pub outbox_pending: AtomicU64,
    pub inbox_pending: AtomicU64,
    pub inbox_undelivered: AtomicU64,
    pub shutdowns: AtomicU64,
    pub fanout_healthy: AtomicBool,
    pub storage_healthy: AtomicBool,
    pub accelerator_sidelined: AtomicBool,
    pub accelerator_configured: AtomicBool,
}

impl Default for GatewayRuntimeMetrics {
    fn default() -> Self {
        Self {
            #[cfg(feature = "postgres")]
            browser: None,
            submissions: AtomicU64::new(0),
            duplicate_submissions: AtomicU64::new(0),
            polls: AtomicU64::new(0),
            fanout_successes: AtomicU64::new(0),
            fanout_failures: AtomicU64::new(0),
            retention_failures: AtomicU64::new(0),
            reconciliation_repairs: AtomicU64::new(0),
            reconciliation_failures: AtomicU64::new(0),
            outbox_read_failures: AtomicU64::new(0),
            outbox_write_failures: AtomicU64::new(0),
            quarantined_rows: AtomicU64::new(0),
            quarantined_current: AtomicU64::new(0),
            outbox_pending: AtomicU64::new(0),
            inbox_pending: AtomicU64::new(0),
            inbox_undelivered: AtomicU64::new(0),
            shutdowns: AtomicU64::new(0),
            fanout_healthy: AtomicBool::new(false),
            storage_healthy: AtomicBool::new(true),
            accelerator_sidelined: AtomicBool::new(false),
            accelerator_configured: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRuntimeSnapshot {
    pub submissions: u64,
    pub duplicate_submissions: u64,
    pub polls: u64,
    pub fanout_successes: u64,
    pub fanout_failures: u64,
    pub retention_failures: u64,
    pub reconciliation_repairs: u64,
    pub reconciliation_failures: u64,
    pub outbox_read_failures: u64,
    pub outbox_write_failures: u64,
    pub quarantined_rows: u64,
    pub quarantined_current: u64,
    pub outbox_pending: u64,
    pub inbox_pending: u64,
    pub inbox_undelivered: u64,
    pub shutdowns: u64,
    pub fanout_healthy: bool,
    pub storage_healthy: bool,
    pub accelerator_sidelined: bool,
    pub accelerator_configured: bool,
}

impl GatewayRuntimeMetrics {
    pub fn new(fanout_configured: bool) -> Self {
        Self {
            fanout_healthy: AtomicBool::new(fanout_configured),
            storage_healthy: AtomicBool::new(true),
            accelerator_configured: AtomicBool::new(false),
            ..Self::default()
        }
    }

    pub fn set_accelerator_configured(&self, configured: bool) {
        self.accelerator_configured
            .store(configured, Ordering::Relaxed);
    }

    pub fn set_accelerator_sidelined(&self, sidelined: bool) {
        self.accelerator_sidelined
            .store(sidelined, Ordering::Relaxed);
    }

    pub fn accelerator_healthy(&self) -> bool {
        !self.accelerator_configured.load(Ordering::Relaxed)
            || !self.accelerator_sidelined.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> GatewayRuntimeSnapshot {
        GatewayRuntimeSnapshot {
            submissions: self.submissions.load(Ordering::Relaxed),
            duplicate_submissions: self.duplicate_submissions.load(Ordering::Relaxed),
            polls: self.polls.load(Ordering::Relaxed),
            fanout_successes: self.fanout_successes.load(Ordering::Relaxed),
            fanout_failures: self.fanout_failures.load(Ordering::Relaxed),
            retention_failures: self.retention_failures.load(Ordering::Relaxed),
            reconciliation_repairs: self.reconciliation_repairs.load(Ordering::Relaxed),
            reconciliation_failures: self.reconciliation_failures.load(Ordering::Relaxed),
            outbox_read_failures: self.outbox_read_failures.load(Ordering::Relaxed),
            outbox_write_failures: self.outbox_write_failures.load(Ordering::Relaxed),
            quarantined_rows: self.quarantined_rows.load(Ordering::Relaxed),
            quarantined_current: self.quarantined_current.load(Ordering::Relaxed),
            outbox_pending: self.outbox_pending.load(Ordering::Relaxed),
            inbox_pending: self.inbox_pending.load(Ordering::Relaxed),
            inbox_undelivered: self.inbox_undelivered.load(Ordering::Relaxed),
            shutdowns: self.shutdowns.load(Ordering::Relaxed),
            fanout_healthy: self.fanout_healthy.load(Ordering::Relaxed),
            storage_healthy: self.storage_healthy.load(Ordering::Relaxed),
            accelerator_sidelined: self.accelerator_sidelined.load(Ordering::Relaxed),
            accelerator_configured: self.accelerator_configured.load(Ordering::Relaxed),
        }
    }

    pub fn status_line(&self, accelerator_sidelined: bool) -> String {
        self.set_accelerator_sidelined(accelerator_sidelined);
        let snapshot = self.snapshot();
        let line = format!(
            "apex_control_gateway_status submissions={} duplicate_submissions={} polls={} fanout_successes={} fanout_failures={} retention_failures={} reconciliation_repairs={} reconciliation_failures={} outbox_read_failures={} outbox_write_failures={} quarantined_rows={} quarantined_current={} outbox_pending={} inbox_pending={} inbox_undelivered={} shutdowns={} fanout_healthy={} storage_healthy={} accelerator_configured={} accelerator_sidelined={}",
            snapshot.submissions,
            snapshot.duplicate_submissions,
            snapshot.polls,
            snapshot.fanout_successes,
            snapshot.fanout_failures,
            snapshot.retention_failures,
            snapshot.reconciliation_repairs,
            snapshot.reconciliation_failures,
            snapshot.outbox_read_failures,
            snapshot.outbox_write_failures,
            snapshot.quarantined_rows,
            snapshot.quarantined_current,
            snapshot.outbox_pending,
            snapshot.inbox_pending,
            snapshot.inbox_undelivered,
            snapshot.shutdowns,
            snapshot.fanout_healthy,
            snapshot.storage_healthy,
            snapshot.accelerator_configured,
            snapshot.accelerator_sidelined,
        );
        #[cfg(feature = "postgres")]
        let line = format!("{line}{}", self.browser_observation_status());
        line
    }
}
