use serde::{Deserialize, Serialize};

use super::error::FindingError;
use super::validate::{valid_field_path, valid_hash};
use crate::is_lowercase_uuidv7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingType {
    TelemetryIntegrity,
    AgentTemplateNoncompliant,
    ScopeIdentityDenied,
    UntrustedControlBoundary,
    SecretExposure,
    ToolPolicyDenied,
    AuthAbuse,
    AdmissionAbuse,
    /// Outbox backlog depth or oldest-pending age crossed the Phase 0.6
    /// item 6 early-warning threshold. Not tied to any single tenant event;
    /// recorded against the reserved operational scope (see
    /// `gateway::core::OPERATIONAL_WORKSPACE_ID`/`OPERATIONAL_NAMESPACE_ID`).
    BacklogDegraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingConfidence {
    Deterministic,
    Corroborated,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Contained,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
    Contain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentAction {
    Pause,
    Quarantine,
    DisableTool,
}

/// Bounded, redacted signals accepted by the deterministic detector boundary.
/// No variant carries prompts, completions, credentials, or raw tool output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySignal {
    TelemetryIntegrity,
    ScopeIdentityDenied,
    UntrustedControlBoundary,
    SecretExposure,
    ToolPolicyDenied,
    AgentTemplateNoncompliant,
    AuthAbuse,
    AdmissionAbuse,
    BacklogDegraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionInput {
    pub signal: SecuritySignal,
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
    pub field_path: String,
    pub value_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub event_id: String,
    pub field_path: String,
    pub value_hash: String,
}

impl EvidenceRef {
    pub fn new(event_id: &str, field_path: &str, value_hash: &str) -> Result<Self, FindingError> {
        if !is_lowercase_uuidv7(event_id)
            || !valid_field_path(field_path)
            || !valid_hash(value_hash)
        {
            return Err(FindingError::invalid_field());
        }
        Ok(Self {
            event_id: event_id.to_owned(),
            field_path: field_path.to_owned(),
            value_hash: value_hash.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub finding_id: String,
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub workspace_id: String,
    pub namespace_id: String,
    pub detector: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_decision: PolicyDecision,
    pub fingerprint: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingInput {
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub workspace_id: String,
    pub namespace_id: String,
    pub detector: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_decision: PolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingStatusUpdate {
    pub finding_id: String,
    pub from: FindingStatus,
    pub to: FindingStatus,
    pub action: Option<ContainmentAction>,
    pub actor_scope: String,
    #[serde(default)]
    pub actor_subject: String,
    pub at_ms: u64,
}
