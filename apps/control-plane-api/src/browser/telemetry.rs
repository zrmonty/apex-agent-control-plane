//! Bounded BFF observations, not durable audit evidence or MCP trace queries.
//!
//! Construct once, clone the process clock, and propagate request context
//! explicitly. Export loss never grants or denies access. Wall representation
//! and acquisition estimates do not establish UTC accuracy or bound later drift.

use apex_telemetry::clock::{Clock, ClockError, ClockSnapshot, ClockSource};
use std::{fmt, io::Write, sync::Arc};

mod export;
mod ids;
mod record;
mod trace;

pub use export::{ExportDisposition, ExportOwner, LossCounters, ShutdownReport};
pub use record::{Action, Completion, RedactedRecord, Stage, StageOutcome, Status};
pub use trace::{RequestContext, RequestTrace};

pub const MAX_STAGES: usize = 32;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const EXPORT_QUEUE_RECORDS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    Clock,
    Entropy,
    Exporter,
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("browser observation initialization failed")
    }
}
impl std::error::Error for InitError {}

trait SampleClock: Send + Sync {
    fn now(&self) -> Result<ClockSnapshot, ClockError>;
}

impl<S: ClockSource> SampleClock for Clock<S> {
    fn now(&self) -> Result<ClockSnapshot, ClockError> {
        Clock::now(self)
    }
}

#[derive(Clone)]
pub struct BrowserTelemetry {
    clock: Arc<dyn SampleClock>,
    process_id: Arc<str>,
    exporter: export::ExportHandle,
    counters: Arc<export::Counters>,
}

impl BrowserTelemetry {
    /// Construct once outside Tokio; clones must share the same process clock.
    pub fn new() -> Result<(Self, ExportOwner), InitError> {
        Self::with_writer(std::io::stderr())
    }

    /// Inject a startup-owned destination while retaining the production clock,
    /// fixed queue/record bounds and dedicated output worker. Never choose this
    /// destination from browser configuration or request data.
    pub fn with_writer(
        writer: impl Write + Send + 'static,
    ) -> Result<(Self, ExportOwner), InitError> {
        let clock = Clock::new().map_err(|_| InitError::Clock)?;
        Self::with_clock_and_writer(clock, writer)
    }

    fn with_clock_and_writer<S: ClockSource + 'static>(
        clock: Clock<S>,
        writer: impl Write + Send + 'static,
    ) -> Result<(Self, ExportOwner), InitError> {
        let process_id = ids::random_hex::<16>()?;
        let counters = Arc::new(export::Counters::default());
        let (exporter, owner) = ExportOwner::new(writer, Arc::clone(&counters))?;
        Ok((
            Self {
                clock: Arc::new(clock),
                process_id: process_id.into(),
                exporter,
                counters,
            },
            owner,
        ))
    }

    pub fn begin(&self, action: Action) -> RequestTrace {
        RequestTrace::new(self.clone(), action)
    }

    /// Never wait for export capacity or perform output I/O on the caller.
    pub fn export(&self, record: &RedactedRecord) -> ExportDisposition {
        self.exporter.export(record)
    }

    pub fn counters(&self) -> LossCounters {
        self.counters.snapshot()
    }
}

#[cfg(test)]
mod tests;
