//! Transport-neutral governance contracts for Apex adapters.

#![warn(missing_docs)]

mod error;
mod traits;
mod types;

pub use error::{GovernanceError, GovernanceInputError, IdentifierKind};
pub use traits::{ApexApproval, ApexEvents, ApexGovernance};
pub use types::{
    ActionName, ApprovalAction, ApprovalDecision, ApprovalOutcome, AuthorizationDecision,
    AuthorizationOutcome, AuthorizationRequest, BackendName, DataClassification, DataSizeSummary,
    EventId, EventReceipt, FieldPath, FilteringSummary, GovernanceScope, PolicyId, PolicySnapshot,
    ReasonCode, ResourceName, RunId, SpanId, ToolExecutionEvent, ToolExecutionMetadata,
    ToolExecutionStatus, ToolName, TraceContext, TraceId,
};

#[cfg(test)]
mod tests;
