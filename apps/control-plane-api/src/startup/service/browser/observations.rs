use apex_control_plane_api::{GatewayRuntimeMetrics, browser::telemetry::ExportOwner};
use std::{io, time::Duration};

pub(in crate::startup::service) fn finish(
    exporter: ExportOwner,
    metrics: &GatewayRuntimeMetrics,
) -> io::Result<()> {
    let report = exporter.shutdown(Duration::from_secs(1));
    let counters = metrics
        .browser_observation_counters()
        .ok_or_else(|| io::Error::other("browser observation counters were not attached"))?;
    if !report.complete
        || counters.dropped_records != 0
        || counters.dropped_stages != 0
        || counters.clock_errors != 0
        || counters.id_errors != 0
        || counters.exporter_errors != 0
        || counters.incomplete_shutdowns != 0
    {
        // Return evidence to the process caller, not to the failed output queue.
        // No fallback output or request-thread I/O. Loss does not change any
        // authorization/result; after drain it makes the process exit degraded.
        return Err(io::Error::other(format!(
            "browser observations degraded: complete={} exported_records={} dropped_records={} dropped_stages={} clock_errors={} id_errors={} exporter_errors={} incomplete_shutdowns={}",
            report.complete,
            counters.exported_records,
            counters.dropped_records,
            counters.dropped_stages,
            counters.clock_errors,
            counters.id_errors,
            counters.exporter_errors,
            counters.incomplete_shutdowns,
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
