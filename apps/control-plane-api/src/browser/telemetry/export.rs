use super::{EXPORT_QUEUE_RECORDS, InitError, MAX_RECORD_BYTES, RedactedRecord};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportDisposition {
    Queued,
    DroppedFull,
    DroppedClosed,
    DroppedOversize,
}

/// Integer process-local observations, not authorization or durability state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LossCounters {
    pub exported_records: u64,
    /// Finalized losses only; records still owned by a blocked output worker
    /// are not counted until that worker can release them.
    pub dropped_records: u64,
    pub dropped_stages: u64,
    pub clock_errors: u64,
    pub id_errors: u64,
    pub exporter_errors: u64,
    pub incomplete_shutdowns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Worker stopped and joined. Exported output is not a durability receipt;
    /// callers must also inspect loss/error counters.
    pub complete: bool,
}

/// Explicit startup-owned exporter lifetime. Drop never joins a worker.
pub struct ExportOwner {
    state: Arc<ExportState>,
    worker: Option<JoinHandle<()>>,
}

impl ExportOwner {
    pub(super) fn new(
        writer: impl Write + Send + 'static,
        counters: Arc<Counters>,
    ) -> Result<(ExportHandle, Self), InitError> {
        let (sender, receiver) = mpsc::sync_channel(EXPORT_QUEUE_RECORDS);
        let state = Arc::new(ExportState {
            accepting: AtomicBool::new(true),
            abort: AtomicBool::new(false),
            counters,
        });
        let worker_state = Arc::clone(&state);
        let worker = thread::Builder::new()
            .name("apex-bff-observations".into())
            .spawn(move || run(writer, receiver, worker_state))
            .map_err(|_| InitError::Exporter)?;
        Ok((
            ExportHandle {
                sender,
                state: Arc::clone(&state),
            },
            Self {
                state,
                worker: Some(worker),
            },
        ))
    }

    /// Invoke outside entered Tokio. The wait is capped at five seconds even
    /// for an excessive caller timeout. Blocked OS output cannot be interrupted;
    /// on timeout the worker detaches and incomplete shutdown is counted at once.
    /// The current write and bounded queue remain owned by that worker until the
    /// write returns. Only then are pending records discarded and their losses
    /// counted. If the write never returns, that accounting remains delayed;
    /// neither cancellation nor successful drainage is claimed.
    pub fn shutdown(mut self, timeout: Duration) -> ShutdownReport {
        self.state.accepting.store(false, Ordering::Release);
        if tokio::runtime::Handle::try_current().is_ok() {
            return self.incomplete();
        }
        let start = Instant::now();
        let budget = timeout.min(Duration::from_secs(5));
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return self.incomplete();
            }
            thread::park_timeout(remaining.min(Duration::from_millis(1)));
        }
        let complete = self
            .worker
            .take()
            .is_none_or(|worker| worker.join().is_ok());
        if !complete {
            add(&self.state.counters.incomplete_shutdowns, 1);
        }
        ShutdownReport { complete }
    }

    fn incomplete(&mut self) -> ShutdownReport {
        self.state.abort.store(true, Ordering::Release);
        add(&self.state.counters.incomplete_shutdowns, 1);
        self.worker.take(); // Detach; no implicit Drop join.
        ShutdownReport { complete: false }
    }
}

impl Drop for ExportOwner {
    fn drop(&mut self) {
        self.state.accepting.store(false, Ordering::Release);
        self.state.abort.store(true, Ordering::Release);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            add(&self.state.counters.incomplete_shutdowns, 1);
        }
        // JoinHandle::drop detaches. No output or blocking cleanup occurs here.
    }
}

#[derive(Default)]
pub(super) struct Counters {
    pub exported_records: AtomicU64,
    pub dropped_records: AtomicU64,
    pub dropped_stages: AtomicU64,
    pub clock_errors: AtomicU64,
    pub id_errors: AtomicU64,
    pub exporter_errors: AtomicU64,
    pub incomplete_shutdowns: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> LossCounters {
        LossCounters {
            exported_records: self.exported_records.load(Ordering::Relaxed),
            dropped_records: self.dropped_records.load(Ordering::Relaxed),
            dropped_stages: self.dropped_stages.load(Ordering::Relaxed),
            clock_errors: self.clock_errors.load(Ordering::Relaxed),
            id_errors: self.id_errors.load(Ordering::Relaxed),
            exporter_errors: self.exporter_errors.load(Ordering::Relaxed),
            incomplete_shutdowns: self.incomplete_shutdowns.load(Ordering::Relaxed),
        }
    }
}

pub(super) fn add(counter: &AtomicU64, count: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(count))
    });
}

struct ExportState {
    accepting: AtomicBool,
    abort: AtomicBool,
    counters: Arc<Counters>,
}

#[derive(Clone)]
pub(super) struct ExportHandle {
    sender: SyncSender<QueuedRecord>,
    state: Arc<ExportState>,
}

impl ExportHandle {
    pub fn export(&self, record: &RedactedRecord) -> ExportDisposition {
        if !self.state.accepting.load(Ordering::Acquire) {
            add(&self.state.counters.dropped_records, 1);
            return ExportDisposition::DroppedClosed;
        }
        let mut line = BoundedLine(Vec::with_capacity(MAX_RECORD_BYTES));
        if serde_json::to_writer(&mut line, record).is_err() {
            add(&self.state.counters.dropped_records, 1);
            return ExportDisposition::DroppedOversize;
        }
        line.0.push(b'\n');
        let record = QueuedRecord {
            bytes: line.0.into_boxed_slice(),
            counters: Arc::clone(&self.state.counters),
            delivered: false,
        };
        // No output lock or I/O is held here. try_send never waits for capacity.
        if !self.state.accepting.load(Ordering::Acquire) {
            return ExportDisposition::DroppedClosed; // RAII counts the loss.
        }
        match self.sender.try_send(record) {
            Ok(()) => ExportDisposition::Queued,
            Err(TrySendError::Full(_)) => ExportDisposition::DroppedFull,
            Err(TrySendError::Disconnected(_)) => ExportDisposition::DroppedClosed,
        }
    }
}

struct BoundedLine(Vec<u8>);
impl Write for BoundedLine {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Include the eventual newline in the 64-KiB queue-item ceiling.
        if bytes.len() > (MAX_RECORD_BYTES - 1).saturating_sub(self.0.len()) {
            return Err(io::Error::other("observation exceeds byte bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct QueuedRecord {
    bytes: Box<[u8]>,
    counters: Arc<Counters>,
    delivered: bool,
}
impl Drop for QueuedRecord {
    fn drop(&mut self) {
        if !self.delivered {
            add(&self.counters.dropped_records, 1);
        }
    }
}

fn run(mut writer: impl Write, receiver: Receiver<QueuedRecord>, state: Arc<ExportState>) {
    let mut exit = WorkerExit {
        state: Arc::clone(&state),
        clean: false,
    };
    loop {
        if state.abort.load(Ordering::Acquire) {
            break;
        }
        let mut record = if state.accepting.load(Ordering::Acquire) {
            match receiver.recv_timeout(Duration::from_millis(5)) {
                Ok(record) => record,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match receiver.try_recv() {
                Ok(record) => record,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        };
        if state.abort.load(Ordering::Acquire) {
            break;
        }
        // One additional <=64-KiB record may be in flight outside the 128-slot
        // (<=8-MiB payload) queue. No telemetry lock spans either output call.
        if writer
            .write_all(&record.bytes)
            .and_then(|()| writer.flush())
            .is_ok()
        {
            record.delivered = true;
            add(&state.counters.exported_records, 1);
        } else {
            add(&state.counters.exporter_errors, 1);
            // A failed write/flush may leave an unterminated JSON prefix. Close
            // admission before dropping the sink; never append another record
            // or count it as delivered on this uncertain framing boundary.
            state.accepting.store(false, Ordering::Release);
            break;
        }
    }
    drop(receiver); // Undelivered queued records account for their own loss.
    drop(writer);
    exit.clean = true;
}

struct WorkerExit {
    state: Arc<ExportState>,
    clean: bool,
}
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.state.accepting.store(false, Ordering::Release);
        if !self.clean {
            add(&self.state.counters.exporter_errors, 1);
        }
    }
}
