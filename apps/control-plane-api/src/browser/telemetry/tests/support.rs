use super::super::*;
use apex_telemetry::clock::{ClockSource, WallClockSample};
use serde_json::Value;
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::ThreadId,
    time::Duration,
};

pub(super) const EPOCH_US: u64 = 9_007_199_254_740_993;
pub(super) const SOURCE: &str = "injected representation estimate; UTC/drift unknown";

#[derive(Clone)]
pub(super) struct Probe {
    pub ns: Arc<AtomicU64>,
    pub wall_us: Arc<AtomicU64>,
    pub wall_reads: Arc<AtomicU64>,
    pub fail: Arc<AtomicBool>,
}

impl Probe {
    pub fn new() -> Self {
        Self {
            ns: Arc::new(AtomicU64::new(0)),
            wall_us: Arc::new(AtomicU64::new(EPOCH_US)),
            wall_reads: Arc::new(AtomicU64::new(0)),
            fail: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn advance(&self, ns: u64) {
        self.ns.fetch_add(ns, Ordering::SeqCst);
    }

    pub fn clock(&self, uncertainty_ns: Option<u128>) -> Clock<Source> {
        Clock::with_source(Source {
            probe: self.clone(),
            uncertainty_ns,
        })
        .expect("valid injected wall anchor")
    }
}

pub(super) struct Source {
    probe: Probe,
    uncertainty_ns: Option<u128>,
}

impl ClockSource for Source {
    fn source(&self) -> &str {
        SOURCE
    }

    fn monotonic_now_ns(&mut self) -> Result<u128, ClockError> {
        if self.probe.fail.load(Ordering::SeqCst) {
            return Err(ClockError::SourceUnavailable);
        }
        Ok(u128::from(self.probe.ns.load(Ordering::SeqCst)))
    }

    fn wall_now(&mut self) -> Result<WallClockSample, ClockError> {
        self.probe.wall_reads.fetch_add(1, Ordering::SeqCst);
        Ok(WallClockSample {
            unix_ns: u128::from(self.probe.wall_us.load(Ordering::SeqCst)) * 1_000,
            resolution_ns: 100,
            uncertainty_ns: self.uncertainty_ns,
        })
    }
}

#[derive(Clone, Default)]
pub(super) struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    threads: Arc<Mutex<Vec<ThreadId>>>,
}

impl Capture {
    pub fn records(&self) -> Vec<Value> {
        self.bytes
            .lock()
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("redacted JSON line"))
            .collect()
    }

    pub fn writer_threads(&self) -> Vec<ThreadId> {
        self.threads.lock().unwrap().clone()
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct Harness {
    pub telemetry: BrowserTelemetry,
    pub probe: Probe,
    pub capture: Capture,
    pub owner: ExportOwner,
}

impl Harness {
    pub fn new() -> Self {
        Self::with_uncertainty(Some(100))
    }

    pub fn with_uncertainty(uncertainty_ns: Option<u128>) -> Self {
        let probe = Probe::new();
        let capture = Capture::default();
        let (telemetry, owner) =
            BrowserTelemetry::with_clock_and_writer(probe.clock(uncertainty_ns), capture.clone())
                .expect("injected observation constructor");
        Self {
            telemetry,
            probe,
            capture,
            owner,
        }
    }

    pub fn close(self) -> ShutdownReport {
        self.owner.shutdown(Duration::from_secs(2))
    }
}

pub(super) fn json(record: RedactedRecord) -> Value {
    serde_json::to_value(record).expect("redacted observation serialization")
}

pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}
