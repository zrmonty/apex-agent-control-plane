use crate::proto::ProxyStageTiming;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Login,
    Callback,
    Session,
    Logout,
    Management,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Ingress,
    LoginAdmission,
    SessionLoad,
    SessionTouch,
    SessionCommit,
    RefreshClaim,
    RefreshCommit,
    LocalRevoke,
    Provider,
    Auth,
    Csrf,
    Crypto,
    Decode,
    Management,
    Serialization,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ingress => "bff.ingress",
            Self::LoginAdmission => "bff.login_admission",
            Self::SessionLoad => "bff.session_load",
            Self::SessionTouch => "bff.session_touch",
            Self::SessionCommit => "bff.session_commit",
            Self::RefreshClaim => "bff.refresh_claim",
            Self::RefreshCommit => "bff.refresh_commit",
            Self::LocalRevoke => "bff.local_revoke",
            Self::Provider => "bff.provider",
            Self::Auth => "bff.auth",
            Self::Csrf => "bff.csrf",
            Self::Crypto => "bff.crypto",
            Self::Decode => "bff.decode",
            Self::Management => "bff.management",
            Self::Serialization => "bff.serialization",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    RateLimited,
    Unavailable,
    Timeout,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    Completed,
    Error,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    /// A handler built a response. No body/socket write or receipt is implied.
    HandlerResponseReady,
    Aborted,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StageObservation {
    pub stage: Stage,
    pub outcome: StageOutcome,
    /// Missing for an unpolled stage or failed clock/identifier acquisition.
    /// Cancelled elapsed timing is an abort boundary, never success evidence.
    pub timing: Option<ProxyStageTiming>,
}

/// Construction is confined to telemetry; there is no arbitrary metadata map.
/// Generated ProxyStageTiming serialization preserves uint64 decimal strings.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedRecord {
    pub(super) request_id: String,
    pub(super) otel_trace_id: String,
    pub(super) root_span_id: String,
    pub(super) process_instance_id: String,
    pub(super) action: Action,
    pub(super) status: Status,
    pub(super) completion: Completion,
    pub(super) partial: bool,
    pub(super) stages: Vec<StageObservation>,
    pub(super) dropped_stages: String,
    pub(super) clock_failures: String,
    pub(super) id_failures: String,
}

impl RedactedRecord {
    pub(super) fn empty(action: Action, status: Status) -> Self {
        Self {
            request_id: String::new(),
            otel_trace_id: String::new(),
            root_span_id: String::new(),
            process_instance_id: String::new(),
            action,
            status,
            completion: Completion::HandlerResponseReady,
            partial: false,
            stages: Vec::new(),
            dropped_stages: "0".into(),
            clock_failures: "0".into(),
            id_failures: "0".into(),
        }
    }

    pub(super) fn enforce_size_bound(&mut self) -> u64 {
        let mut dropped = 0_u64;
        loop {
            let mut size = SizeBound(0);
            if serde_json::to_writer(&mut size, &self).is_ok() {
                return dropped;
            }
            self.partial = true;
            if self.stages.pop().is_none() {
                return dropped;
            }
            dropped = dropped.saturating_add(1);
            let previous = self.dropped_stages.parse::<u64>().unwrap_or(u64::MAX);
            self.dropped_stages = previous.saturating_add(1).to_string();
        }
    }
}

// Counts generated JSON bytes without constructing another full record buffer.
// A header made only of fixed enums and generated bounded IDs always fits.
struct SizeBound(usize);
impl Write for SizeBound {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > (super::MAX_RECORD_BYTES - 1).saturating_sub(self.0) {
            return Err(io::Error::other("observation exceeds byte bound"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
