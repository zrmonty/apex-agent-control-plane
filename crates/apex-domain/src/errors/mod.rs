//! Redacted gateway errors and AI-safe diagnostic reports.

mod code;
mod diagnostics;
mod gateway;

#[cfg(test)]
mod tests;

pub use code::GatewayErrorCode;
pub use diagnostics::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, RedactionSummary,
};
pub use gateway::GatewayError;


