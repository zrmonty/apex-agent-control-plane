//! Shared security finding and evidence boundary.
//!
//! Findings are immutable, scoped, redacted records. This crate owns their
//! validation and deterministic classification; applications provide durable
//! journals or other persistence around the store.

mod detect;
mod error;
mod ids;
mod store;
mod types;
mod validate;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_ids;

pub use apex_domain::{Caller, is_lowercase_uuidv7, is_scope_identifier};
pub use detect::{detect_and_record, detection_finding};
pub use error::{FindingError, FindingErrorCode};
pub use store::FindingStore;
pub use types::{
    ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingSeverity,
    FindingStatus, FindingStatusUpdate, FindingType, PolicyDecision, SecurityFinding,
    SecuritySignal,
};
