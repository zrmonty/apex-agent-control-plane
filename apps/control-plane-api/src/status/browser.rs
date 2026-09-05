//! Browser observation counters are read independently of the export queue.
use super::GatewayRuntimeMetrics;
use crate::browser::telemetry::{BrowserTelemetry, LossCounters};
use std::fmt::{self, Write};

pub(super) struct BrowserObservations(BrowserTelemetry);

impl fmt::Debug for BrowserObservations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.counters().fmt(formatter)
    }
}

impl GatewayRuntimeMetrics {
    pub fn with_browser_observations(mut self, telemetry: BrowserTelemetry) -> Self {
        self.browser = Some(BrowserObservations(telemetry));
        self
    }

    pub fn browser_observation_counters(&self) -> Option<LossCounters> {
        self.browser.as_ref().map(|browser| browser.0.counters())
    }

    pub fn browser_observation_prometheus(&self) -> String {
        let Some(counters) = self.browser_observation_counters() else {
            return String::new();
        };
        let mut text = String::with_capacity(1024);
        for (name, value) in values(counters) {
            // Names are fixed literals, with no identity/request labels.
            let _ = writeln!(
                text,
                "# TYPE apex_browser_observation_{name}_total counter\napex_browser_observation_{name}_total {value}"
            );
        }
        text
    }

    pub(super) fn browser_observation_status(&self) -> String {
        let Some(counters) = self.browser_observation_counters() else {
            return String::new();
        };
        let mut text = String::with_capacity(256);
        for (name, value) in values(counters) {
            let _ = write!(text, " browser_{name}={value}");
        }
        text
    }
}

fn values(counters: LossCounters) -> [(&'static str, u64); 7] {
    [
        ("exported_records", counters.exported_records),
        ("dropped_records", counters.dropped_records),
        ("dropped_stages", counters.dropped_stages),
        ("clock_errors", counters.clock_errors),
        ("id_errors", counters.id_errors),
        ("exporter_errors", counters.exporter_errors),
        ("incomplete_shutdowns", counters.incomplete_shutdowns),
    ]
}
