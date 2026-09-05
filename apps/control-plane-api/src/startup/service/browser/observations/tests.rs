use super::*;
use apex_control_plane_api::browser::telemetry::{Action, BrowserTelemetry, Status};
use std::{io::Write, sync::mpsc, time::Instant};

struct Failing;
impl Write for Failing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("must-not-be-exposed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn clean_export_shutdown_is_successful_and_retains_integer_snapshot() {
    let (telemetry, owner) = BrowserTelemetry::with_writer(io::sink()).unwrap();
    let metrics = GatewayRuntimeMetrics::default().with_browser_observations(telemetry.clone());
    telemetry.export(&telemetry.begin(Action::Session).finish(Status::Ok));
    finish(owner, &metrics).unwrap();
    let counters = metrics
        .browser_observation_counters()
        .expect("configured observations");
    assert_eq!(counters.exported_records, 1);
    assert_eq!(counters.dropped_records, 0);
    assert_eq!(counters.incomplete_shutdowns, 0);
}

#[test]
fn failed_export_shutdown_returns_only_fixed_counter_evidence() {
    let (telemetry, owner) = BrowserTelemetry::with_writer(Failing).unwrap();
    let metrics = GatewayRuntimeMetrics::default().with_browser_observations(telemetry.clone());
    telemetry.export(&telemetry.begin(Action::Session).finish(Status::Ok));
    let error = finish(owner, &metrics).expect_err("lost observation must remain visible at exit");
    let text = error.to_string();
    assert!(text.contains("dropped_records=1"));
    assert!(text.contains("exporter_errors=1"));
    assert!(!text.contains("must-not-be-exposed"));
}

struct Blocked {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    exited: mpsc::Sender<()>,
}
impl Write for Blocked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        // Independent watchdog prevents a failed assertion from hanging this test.
        self.release.recv_timeout(Duration::from_secs(4)).unwrap();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Blocked {
    fn drop(&mut self) {
        let _ = self.exited.send(());
    }
}

#[test]
fn blocked_export_shutdown_returns_bounded_error_without_fallback_output() {
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (exited, stopped) = mpsc::channel();
    let (telemetry, owner) = BrowserTelemetry::with_writer(Blocked {
        entered,
        release: blocked,
        exited,
    })
    .unwrap();
    let metrics = GatewayRuntimeMetrics::default().with_browser_observations(telemetry.clone());
    telemetry.export(&telemetry.begin(Action::Session).finish(Status::Ok));
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    let start = Instant::now();
    let result = finish(owner, &metrics);
    let elapsed = start.elapsed();
    release.send(()).unwrap();
    stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(elapsed < Duration::from_secs(2));
    let text = result
        .expect_err("incomplete shutdown must reach the process outcome")
        .to_string();
    assert!(text.contains("complete=false"));
    assert!(text.contains("incomplete_shutdowns=1"));
}
