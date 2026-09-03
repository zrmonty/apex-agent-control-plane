//! Transport-neutral governance contracts for Apex adapters.

#![warn(missing_docs)]

mod error;
mod types;

pub use error::{GovernanceInputError, IdentifierKind};
pub use types::{
    ActionName, BackendName, EventId, FieldPath, GovernanceScope, PolicyId, ReasonCode,
    ResourceName, RunId, SpanId, ToolName, TraceContext, TraceId,
};

#[cfg(test)]
mod tests;
