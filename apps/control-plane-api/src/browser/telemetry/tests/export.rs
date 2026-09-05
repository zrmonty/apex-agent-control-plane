use super::super::*;
use super::support::*;
use std::{
    io::{self, Write},
    sync::mpsc::{self, Receiver, SyncSender},
    time::{Duration, Instant},
};

#[test]
fn production_constructor_uses_real_clock_metadata_and_nonblocking_owner_drop() {
    let (telemetry, owner) = BrowserTelemetry::new().expect("production observation constructor");
    let trace = telemetry.begin(Action::Session);
    trace.stage_sync(Stage::Auth, || Ok::<_, ()>(())).unwrap();
    let record = json(trace.finish(Status::Ok));
    let timing = &record["stages"][0]["timing"];
    assert!(timing["clockSource"].as_str().is_some_and(|source| {
        source.contains("std::time::Instant") && source.contains("UTC/drift unknown")
    }));
    assert!(owner.shutdown(Duration::from_secs(2)).complete);
}

#[test]
fn startup_owned_writer_injection_preserves_the_production_clock_and_export_worker() {
    let capture = Capture::default();
    let producer = std::thread::current().id();
    let (telemetry, owner) = BrowserTelemetry::with_writer(capture.clone())
        .expect("startup-owned observation destination");
    let trace = telemetry.begin(Action::Session);
    trace.stage_sync(Stage::Auth, || Ok::<_, ()>(())).unwrap();
    assert_eq!(
        telemetry.export(&trace.finish(Status::Ok)),
        ExportDisposition::Queued
    );
    assert!(owner.shutdown(Duration::from_secs(2)).complete);
    let records = capture.records();
    assert_eq!(records.len(), 1);
    assert!(
        records[0]["stages"][0]["timing"]["clockSource"]
            .as_str()
            .is_some_and(|source| {
                source.contains("std::time::Instant") && source.contains("UTC/drift unknown")
            })
    );
    assert_eq!(records[0]["completion"], "handler_response_ready");
    assert!(!capture.writer_threads().is_empty());
    assert!(
        capture
            .writer_threads()
            .iter()
            .all(|thread| *thread != producer)
    );
    assert_eq!(telemetry.counters().exported_records, 1);
}

#[test]
fn export_writes_only_on_a_dedicated_worker_and_preserves_generated_json() {
    let harness = Harness::new();
    let capture = harness.capture.clone();
    let producer = std::thread::current().id();
    runtime().block_on(async {
        let trace = harness.telemetry.begin(Action::Session);
        trace
            .stage(Stage::SessionLoad, async {
                harness.probe.advance(7_000);
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        assert_eq!(
            harness.telemetry.export(&trace.finish(Status::Ok)),
            ExportDisposition::Queued
        );
    });
    let telemetry = harness.telemetry.clone();
    assert!(harness.close().complete);
    let records = capture.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["stages"][0]["timing"]["durationUs"], "7");
    assert!(!capture.writer_threads().is_empty());
    assert!(
        capture
            .writer_threads()
            .iter()
            .all(|thread| *thread != producer)
    );
    assert_eq!(telemetry.counters().exported_records, 1);
}

#[test]
fn export_queue_has_exactly_128_bounded_slots_and_reports_overflow_without_waiting() {
    let probe = Probe::new();
    let (writer, gate) = blocked_writer();
    let (telemetry, owner) = BrowserTelemetry::with_clock_and_writer(probe.clock(Some(0)), writer)
        .expect("injected observation constructor");
    let record = telemetry.begin(Action::Session).finish(Status::Ok);
    assert_eq!(telemetry.export(&record), ExportDisposition::Queued);
    gate.wait_started();
    let (sent, completed) = mpsc::sync_channel(1);
    let producer = telemetry.clone();
    let worker = std::thread::spawn(move || {
        let mut queued = 0;
        for _ in 0..128 {
            queued += usize::from(producer.export(&record) == ExportDisposition::Queued);
        }
        let overflow = producer.export(&record);
        sent.send((queued, overflow)).unwrap();
    });
    let (queued, overflow) = completed
        .recv_timeout(Duration::from_secs(2))
        .expect("full export queue must not block producer");
    worker.join().expect("bounded export producer");
    assert_eq!(queued, 128);
    assert_eq!(overflow, ExportDisposition::DroppedFull);
    assert_eq!(telemetry.counters().dropped_records, 1);
    gate.release();
    assert!(owner.shutdown(Duration::from_secs(2)).complete);
}

#[test]
fn blocked_output_produces_bounded_incomplete_shutdown_outside_tokio() {
    let probe = Probe::new();
    let (writer, gate) = blocked_writer();
    let (telemetry, owner) = BrowserTelemetry::with_clock_and_writer(probe.clock(Some(0)), writer)
        .expect("injected observation constructor");
    let record = telemetry.begin(Action::Session).finish(Status::Ok);
    assert_eq!(telemetry.export(&record), ExportDisposition::Queued);
    gate.wait_started();
    let (sent, done) = mpsc::sync_channel(1);
    let start = Instant::now();
    let shutdown = std::thread::spawn(move || {
        sent.send(owner.shutdown(Duration::from_millis(10)))
            .unwrap();
    });
    let report = done
        .recv_timeout(Duration::from_secs(2))
        .expect("shutdown must return while output remains blocked");
    shutdown.join().expect("explicit shutdown worker");
    assert!(!report.complete);
    // A generous liveness bound, not a timing-accuracy assertion.
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(telemetry.counters().incomplete_shutdowns, 1);
    assert_eq!(telemetry.export(&record), ExportDisposition::DroppedClosed);
    gate.release_and_wait_finished();
}

#[test]
fn dropping_export_owner_never_implicitly_joins_blocked_output() {
    let probe = Probe::new();
    let (writer, gate) = blocked_writer();
    let (telemetry, owner) = BrowserTelemetry::with_clock_and_writer(probe.clock(Some(0)), writer)
        .expect("injected observation constructor");
    let record = telemetry.begin(Action::Session).finish(Status::Ok);
    assert_eq!(telemetry.export(&record), ExportDisposition::Queued);
    gate.wait_started();
    let (sent, done) = mpsc::sync_channel(1);
    let start = Instant::now();
    let dropping = std::thread::spawn(move || {
        drop(owner);
        sent.send(()).unwrap();
    });
    done.recv_timeout(Duration::from_secs(2))
        .expect("owner Drop must return while output remains blocked");
    dropping.join().expect("owner Drop worker");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(telemetry.export(&record), ExportDisposition::DroppedClosed);
    gate.release_and_wait_finished();
}

#[test]
fn partial_write_failure_closes_exporter_and_accounts_queued_and_future_records() {
    use std::sync::{Arc, Mutex};

    const PREFIX_BYTES: usize = 7;
    struct RecoveringPrefixWriter {
        written: Arc<Mutex<Vec<u8>>>,
        phase: u8,
        failing: SyncSender<()>,
        release: Receiver<()>,
        progress: SyncSender<()>,
    }
    impl Write for RecoveringPrefixWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.phase {
                0 => {
                    let count = bytes.len().min(PREFIX_BYTES);
                    self.written
                        .lock()
                        .unwrap()
                        .extend_from_slice(&bytes[..count]);
                    self.phase = 1;
                    Ok(count)
                }
                1 => {
                    self.phase = 2;
                    let _ = self.failing.try_send(());
                    self.release
                        .recv()
                        .map_err(|_| io::Error::other("fixture gate closed"))?;
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "synthetic partial write failure",
                    ))
                }
                _ => {
                    // This sink would recover. Reusing it without reframing
                    // incorrectly attaches the next JSON record to A's prefix.
                    self.written.lock().unwrap().extend_from_slice(bytes);
                    let _ = self.progress.try_send(());
                    Ok(bytes.len())
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for RecoveringPrefixWriter {
        fn drop(&mut self) {
            let _ = self.progress.try_send(());
        }
    }
    struct Release(SyncSender<()>);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }

    let written = Arc::new(Mutex::new(Vec::new()));
    let (failing_tx, failing) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release = Release(release_tx);
    let (progress_tx, progress) = mpsc::sync_channel(1);
    let (telemetry, owner) = BrowserTelemetry::with_writer(RecoveringPrefixWriter {
        written: Arc::clone(&written),
        phase: 0,
        failing: failing_tx,
        release: release_rx,
        progress: progress_tx,
    })
    .expect("recoverable partial-write observation destination");

    let first = telemetry.begin(Action::Session);
    assert_eq!(
        first.stage_sync(Stage::SessionLoad, || Ok::<_, ()>(37)),
        Ok(37)
    );
    assert_eq!(
        telemetry.export(&first.finish(Status::Ok)),
        ExportDisposition::Queued
    );
    failing
        .recv_timeout(Duration::from_secs(2))
        .expect("prefix written before gated failure");
    let second = telemetry.begin(Action::Management);
    assert_eq!(
        second.stage_sync(Stage::Management, || Err::<(), _>(41)),
        Err(41)
    );
    assert_eq!(
        telemetry.export(&second.finish(Status::Forbidden)),
        ExportDisposition::Queued
    );
    // B is now queued while A is inside the write that will fail.
    let _ = release.0.try_send(());
    // Observe either correct writer closure or the faulty recovery attempt.
    // This handshake never relies on sleeps or shutdown to close the exporter.
    progress
        .recv_timeout(Duration::from_secs(2))
        .expect("exporter reacted to partial-write failure");
    let later = telemetry.begin(Action::Session).finish(Status::Ok);
    let later_disposition = telemetry.export(&later);
    assert!(owner.shutdown(Duration::from_secs(2)).complete);

    let counters = telemetry.counters();
    assert_eq!(
        counters.exported_records, 0,
        "no record after a corrupt prefix is delivered"
    );
    assert_eq!(later_disposition, ExportDisposition::DroppedClosed);
    assert_eq!(counters.exporter_errors, 1);
    assert_eq!(counters.dropped_records, 3);
    assert_eq!(written.lock().unwrap().len(), PREFIX_BYTES);
}

#[test]
fn exporter_io_failure_is_counted_without_changing_request_result() {
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic output failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let probe = Probe::new();
    let (telemetry, owner) =
        BrowserTelemetry::with_clock_and_writer(probe.clock(Some(0)), FailingWriter)
            .expect("injected observation constructor");
    let trace = telemetry.begin(Action::Management);
    assert_eq!(
        trace.stage_sync(Stage::Management, || Ok::<_, ()>(37)),
        Ok(37)
    );
    let record = trace.finish(Status::Ok);
    assert_eq!(telemetry.export(&record), ExportDisposition::Queued);
    assert!(owner.shutdown(Duration::from_secs(2)).complete);
    assert_eq!(telemetry.counters().exported_records, 0);
    assert!(telemetry.counters().exporter_errors > 0);
    assert!(telemetry.counters().dropped_records > 0);
}

struct BlockedWriter {
    started: SyncSender<()>,
    release: Option<Receiver<()>>,
    finished: SyncSender<()>,
}

impl Write for BlockedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(release) = self.release.take() {
            let _ = self.started.try_send(());
            release
                .recv()
                .map_err(|_| io::Error::other("fixture gate closed"))?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BlockedWriter {
    fn drop(&mut self) {
        let _ = self.finished.try_send(());
    }
}

struct Gate {
    started: Receiver<()>,
    release: SyncSender<()>,
    finished: Receiver<()>,
}

impl Gate {
    fn wait_started(&self) {
        self.started
            .recv_timeout(Duration::from_secs(2))
            .expect("export worker entered output");
    }
    fn release(&self) {
        let _ = self.release.try_send(());
    }
    fn release_and_wait_finished(&self) {
        self.release();
        self.finished
            .recv_timeout(Duration::from_secs(2))
            .expect("released output worker stopped");
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        // Always release the owned test worker, including assertion unwinding.
        self.release();
    }
}

fn blocked_writer() -> (BlockedWriter, Gate) {
    let (started_tx, started) = mpsc::sync_channel(1);
    let (release, release_rx) = mpsc::sync_channel(1);
    let (finished_tx, finished) = mpsc::sync_channel(1);
    (
        BlockedWriter {
            started: started_tx,
            release: Some(release_rx),
            finished: finished_tx,
        },
        Gate {
            started,
            release,
            finished,
        },
    )
}
