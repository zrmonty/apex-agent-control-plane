//! Shared Apex domain primitives for authenticated event admission.
//!
//! The domain crate owns the validation, canonical integrity, caller identity,
//! permission, and redacted error contracts used by multiple service apps.

mod errors;
pub mod permissions;
mod runtime_manifest;
mod validation;

pub use apex_contract::proto;

pub use errors::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, RedactionSummary,
};
pub use runtime_manifest::{RuntimeManifestEncodingError, runtime_manifest_hash};
pub use validation::{Caller, IngestRequest, canonical_event_hash};
pub use validation::{is_lowercase_uuidv7, is_scope_identifier};

/// Maximum admitted serialized event-envelope size: 256 KiB.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
