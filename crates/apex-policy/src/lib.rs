//! Transport-neutral governance contracts for Apex adapters.

#![warn(missing_docs)]

mod error;
mod execution_types;
mod traits;
mod types;

pub use error::{GovernanceError, GovernanceInputError, IdentifierKind};
pub use execution_types::{
    ApprovalDecision, ApprovalOutcome, DataSizeSummary, EventReceipt, FilteringSummary,
    ToolExecutionEvent, ToolExecutionMetadata, ToolExecutionStatus,
};
pub use traits::{ApexApproval, ApexEvents, ApexGovernance};
pub use types::{
    ActionName, ApprovalAction, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    BackendName, DataClassification, EventId, FieldPath, GovernanceScope, PolicyId, PolicySnapshot,
    ReasonCode, ResourceName, RunId, SpanId, ToolName, TraceContext, TraceId,
};

#[cfg(test)]
mod tests;
