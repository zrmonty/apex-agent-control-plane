use std::sync::atomic::{AtomicU64, Ordering};

/// Low-cardinality runtime counters emitted by the gateway's periodic status
/// line. They are deliberately independent of a metrics dependency so the
/// control channel keeps its small, failure-tolerant dependency surface.
#[derive(Debug, Default)]
pub struct GatewayRuntimeMetrics {
    pub submissions: AtomicU64,
    pub duplicate_submissions: AtomicU64,
    pub polls: AtomicU64,
    pub fanout_successes: AtomicU64,
    pub fanout_failures: AtomicU64,
    pub retention_failures: AtomicU64,
    pub reconciliation_repairs: AtomicU64,
    pub reconciliation_failures: AtomicU64,
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
}

impl GatewayRuntimeMetrics {
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
        }
    }

    pub fn status_line(&self, accelerator_sidelined: bool) -> String {
        let snapshot = self.snapshot();
        format!(
            "apex_control_gateway_status submissions={} duplicate_submissions={} polls={} fanout_successes={} fanout_failures={} retention_failures={} reconciliation_repairs={} reconciliation_failures={} accelerator_sidelined={accelerator_sidelined}",
            snapshot.submissions,
            snapshot.duplicate_submissions,
            snapshot.polls,
            snapshot.fanout_successes,
            snapshot.fanout_failures,
            snapshot.retention_failures,
            snapshot.reconciliation_repairs,
            snapshot.reconciliation_failures,
        )
    }
}
