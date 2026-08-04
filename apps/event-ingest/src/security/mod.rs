//! Security Alerts foundation: immutable findings, redacted detection input,
//! and a bounded in-process store with scoped reads.

mod detect;
mod error;
mod ids;
mod store;
mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use detect::detect_and_record;
pub(crate) use detect::detection_finding;
pub use error::{FindingError, FindingErrorCode};
pub use store::FindingStore;
pub use types::{
    ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingSeverity,
    FindingStatus, FindingStatusUpdate, FindingType, PolicyDecision, SecurityFinding,
    SecuritySignal,
};
