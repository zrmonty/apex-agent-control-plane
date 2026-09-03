//! Transport-neutral governance contracts for Apex adapters.

#![warn(missing_docs)]

mod error;
mod types;

pub use error::{GovernanceError, GovernanceInputError, IdentifierKind};
pub use types::{
    ActionName, ApprovalAction, ApprovalDecision, ApprovalOutcome, AuthorizationDecision,
    AuthorizationOutcome, AuthorizationRequest, BackendName, DataClassification, EventId,
    FieldPath, GovernanceScope, PolicyId, PolicySnapshot, ReasonCode, ResourceName, RunId, SpanId,
    ToolName, TraceContext, TraceId,
};

#[cfg(test)]
mod tests;
