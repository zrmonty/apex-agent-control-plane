use super::{
    Action, BrowserTelemetry, Completion, MAX_STAGES, RedactedRecord, Stage, StageOutcome, Status,
    export::add, ids, record::StageObservation,
};
use crate::proto::ProxyStageTiming;
use apex_telemetry::clock::{ClockError, ClockSnapshot, duration_ns, duration_us};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

/// The owning request scope. An unfinished Drop must emit partial exactly once.
pub struct RequestTrace {
    context: RequestContext,
    finished: bool,
}

/// Explicit cloneable extension handle; it does not own request finalization.
#[derive(Clone)]
pub struct RequestContext {
    state: Arc<RequestState>,
}

struct RequestState {
    telemetry: BrowserTelemetry,
    action: Action,
    open: Mutex<Option<OpenRequest>>,
}

struct OpenRequest {
    record: RedactedRecord,
    stages: Vec<StageSlot>,
    dropped: u64,
    clock_errors: u64,
    id_errors: u64,
}

struct StageSlot {
    stage: Stage,
    span_id: Option<String>,
    started: Option<ClockSnapshot>,
    outcome: Option<StageOutcome>,
    timing: Option<ProxyStageTiming>,
}

impl RequestTrace {
    pub(super) fn new(telemetry: BrowserTelemetry, action: Action) -> Self {
        let mut open = OpenRequest {
            record: RedactedRecord::empty(action, Status::Cancelled),
            stages: Vec::with_capacity(MAX_STAGES),
            dropped: 0,
            clock_errors: 0,
            id_errors: 0,
        };
        open.record.process_instance_id = telemetry.process_id.to_string();
        match telemetry.clock.now() {
            Ok(snapshot) => match ids::request_id(snapshot.unix_us) {
                Ok(id) => open.record.request_id = id,
                Err(_) => open.id_failure(&telemetry),
            },
            Err(_) => open.clock_failure(&telemetry),
        }
        match ids::random_hex::<16>() {
            Ok(id) => open.record.otel_trace_id = id,
            Err(_) => open.id_failure(&telemetry),
        }
        match ids::random_hex::<8>() {
            Ok(id) => open.record.root_span_id = id,
            Err(_) => open.id_failure(&telemetry),
        }
        Self {
            context: RequestContext {
                state: Arc::new(RequestState {
                    telemetry,
                    action,
                    open: Mutex::new(Some(open)),
                }),
            },
            finished: false,
        }
    }

    pub fn context(&self) -> RequestContext {
        self.context.clone()
    }

    pub fn stage<T, E>(
        &self,
        stage: Stage,
        operation: impl Future<Output = Result<T, E>>,
    ) -> impl Future<Output = Result<T, E>> {
        self.context.stage(stage, operation)
    }

    pub fn stage_sync<T, E>(
        &self,
        stage: Stage,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.context.stage_sync(stage, operation)
    }

    /// Return an observation for explicit export, suppressing abort-on-Drop.
    pub fn finish(mut self, status: Status) -> RedactedRecord {
        self.finished = true;
        self.context.state.finalize(status, false)
    }
}

impl Drop for RequestTrace {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            let record = self.context.state.finalize(Status::Cancelled, true);
            self.context.state.telemetry.export(&record);
        }
    }
}

impl RequestContext {
    pub fn stage<T, E>(
        &self,
        stage: Stage,
        operation: impl Future<Output = Result<T, E>>,
    ) -> impl Future<Output = Result<T, E>> {
        Measured {
            guard: StageGuard::new(Arc::clone(&self.state), stage),
            operation: Box::pin(operation),
        }
    }

    pub fn stage_sync<T, E>(
        &self,
        stage: Stage,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let mut guard = StageGuard::new(Arc::clone(&self.state), stage);
        guard.start();
        let result = operation();
        guard.complete(if result.is_ok() {
            StageOutcome::Completed
        } else {
            StageOutcome::Error
        });
        result
    }
}

impl RequestState {
    fn lock(&self) -> MutexGuard<'_, Option<OpenRequest>> {
        match self.open.lock() {
            Ok(open) => open,
            Err(poisoned) => {
                let mut open = poisoned.into_inner();
                if let Some(request) = open.as_mut() {
                    request.record.partial = true;
                }
                open
            }
        }
    }

    fn reserve(&self, stage: Stage) -> Option<usize> {
        let index = {
            let mut state = self.lock();
            let Some(open) = state.as_mut() else {
                add(&self.telemetry.counters.dropped_stages, 1);
                return None;
            };
            if open.stages.len() >= MAX_STAGES {
                open.dropped = open.dropped.saturating_add(1);
                open.record.partial = true;
                add(&self.telemetry.counters.dropped_stages, 1);
                return None;
            }
            let index = open.stages.len();
            open.stages.push(StageSlot {
                stage,
                span_id: None,
                started: None,
                outcome: None,
                timing: None,
            });
            index
        };
        // Entropy acquisition is outside the request lock, as are clock reads,
        // operation calls/polls, record serialization and all exporter output.
        let span_id = ids::random_hex::<8>();
        if let Some(open) = self.lock().as_mut() {
            match span_id {
                Ok(id) => open.stages[index].span_id = Some(id),
                Err(_) => open.id_failure(&self.telemetry),
            }
        }
        Some(index)
    }

    fn start(&self, index: usize) {
        let sample = self.telemetry.clock.now();
        if let Some(open) = self.lock().as_mut() {
            match sample {
                Ok(sample) => open.stages[index].started = Some(sample),
                Err(_) => open.clock_failure(&self.telemetry),
            }
        }
    }

    fn complete(&self, index: usize, outcome: StageOutcome, polled: bool) {
        let end = polled.then(|| self.telemetry.clock.now());
        if let Some(open) = self.lock().as_mut() {
            open.complete(index, outcome, end.as_ref(), &self.telemetry);
        }
    }

    fn finalize(&self, status: Status, aborted: bool) -> RedactedRecord {
        // Removing the request is the single finalization point. Surviving
        // extension handles cannot reopen it or mutate an exported snapshot.
        let open = self.lock().take();
        let Some(mut open) = open else {
            let mut record = RedactedRecord::empty(self.action, status);
            record.partial = true;
            record.completion = Completion::Aborted;
            return record;
        };
        let needs_end = open
            .stages
            .iter()
            .any(|stage| stage.outcome.is_none() && stage.started.is_some());
        let end = needs_end.then(|| self.telemetry.clock.now());
        for index in 0..open.stages.len() {
            if open.stages[index].outcome.is_none() {
                let stage_end = if open.stages[index].started.is_some() {
                    end.as_ref()
                } else {
                    None
                };
                open.complete(index, StageOutcome::Cancelled, stage_end, &self.telemetry);
            }
        }
        open.record.status = status;
        open.record.completion = if aborted || status == Status::Cancelled {
            Completion::Aborted
        } else {
            Completion::HandlerResponseReady
        };
        open.record.partial |= aborted || matches!(status, Status::Timeout | Status::Cancelled);
        open.record.stages = open
            .stages
            .into_iter()
            .map(|stage| StageObservation {
                stage: stage.stage,
                outcome: stage.outcome.unwrap_or(StageOutcome::Cancelled),
                timing: stage.timing,
            })
            .collect();
        open.record.dropped_stages = open.dropped.to_string();
        open.record.clock_failures = open.clock_errors.to_string();
        open.record.id_failures = open.id_errors.to_string();
        let extra = open.record.enforce_size_bound();
        add(&self.telemetry.counters.dropped_stages, extra);
        open.record
    }
}

impl OpenRequest {
    fn clock_failure(&mut self, telemetry: &BrowserTelemetry) {
        self.record.partial = true;
        self.clock_errors = self.clock_errors.saturating_add(1);
        add(&telemetry.counters.clock_errors, 1);
    }

    fn id_failure(&mut self, telemetry: &BrowserTelemetry) {
        self.record.partial = true;
        self.id_errors = self.id_errors.saturating_add(1);
        add(&telemetry.counters.id_errors, 1);
    }

    fn complete(
        &mut self,
        index: usize,
        outcome: StageOutcome,
        end: Option<&Result<ClockSnapshot, ClockError>>,
        telemetry: &BrowserTelemetry,
    ) {
        let timing = match end {
            Some(Ok(end)) => measurement(&self.record, &self.stages[index], end),
            Some(Err(error)) => Err(*error),
            None => Ok(None),
        };
        let timing = match timing {
            Ok(timing) => timing,
            Err(_) => {
                self.clock_failure(telemetry);
                None
            }
        };
        self.record.partial |= outcome == StageOutcome::Cancelled;
        let slot = &mut self.stages[index];
        slot.timing = timing;
        slot.outcome = Some(outcome);
        slot.started = None;
    }
}

fn measurement(
    record: &RedactedRecord,
    slot: &StageSlot,
    end: &ClockSnapshot,
) -> Result<Option<ProxyStageTiming>, ClockError> {
    let (Some(start), Some(span_id)) = (&slot.started, &slot.span_id) else {
        return Ok(None);
    };
    if record.otel_trace_id.is_empty() || record.root_span_id.is_empty() {
        return Ok(None);
    }
    let from = u128::from(start.monotonic_ns);
    let to = u128::from(end.monotonic_ns);
    Ok(Some(ProxyStageTiming {
        name: slot.stage.name().into(),
        started_at_unix_us: start.unix_us,
        duration_us: duration_us(from, to)?,
        duration_ns: Some(duration_ns(from, to)?),
        otel_trace_id: record.otel_trace_id.clone(),
        span_id: span_id.clone(),
        parent_span_id: record.root_span_id.clone(),
        process_instance_id: record.process_instance_id.clone(),
        clock_source: start.source.clone(),
        clock_resolution_ns: start.resolution_ns,
        clock_uncertainty_us: start.uncertainty_us,
    }))
}

struct StageGuard {
    state: Arc<RequestState>,
    index: Option<usize>,
    polled: bool,
}

impl StageGuard {
    fn new(state: Arc<RequestState>, stage: Stage) -> Self {
        let index = state.reserve(stage);
        Self {
            state,
            index,
            polled: false,
        }
    }

    fn start(&mut self) {
        if !self.polled {
            self.polled = true;
            if let Some(index) = self.index {
                self.state.start(index);
            }
        }
    }

    fn complete(&mut self, outcome: StageOutcome) {
        if let Some(index) = self.index.take() {
            self.state.complete(index, outcome, self.polled);
        }
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        self.complete(StageOutcome::Cancelled);
    }
}

struct Measured<F> {
    // Mark cancellation before destroying the inner future. No result/error
    // text, future state or destructor data is inspected by telemetry.
    guard: StageGuard,
    operation: Pin<Box<F>>,
}

impl<F, T, E> Future for Measured<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.guard.start();
        match this.operation.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.guard.complete(if result.is_ok() {
                    StageOutcome::Completed
                } else {
                    StageOutcome::Error
                });
                Poll::Ready(result)
            }
        }
    }
}
