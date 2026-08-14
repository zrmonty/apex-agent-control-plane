use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::error::FindingError;
use super::types::{
    EvidenceRef, FindingConfidence, FindingSeverity, FindingStatus, FindingType, PolicyDecision,
    SecurityFinding,
};
use crate::{is_lowercase_uuidv7, is_scope_identifier};

pub(crate) const MAX_FINDINGS: usize = 1_000_000;
pub(crate) const MAX_EVIDENCE_REFS: usize = 32;
pub(crate) const MAX_STATUS_UPDATES_PER_FINDING: usize = 3;
pub(crate) const MAX_ACTOR_SCOPE_BYTES: usize = 256;

pub(crate) fn validate_finding(f: &SecurityFinding) -> Result<(), FindingError> {
    validate_scope(&f.workspace_id, &f.namespace_id)?;
    let (expected_severity, expected_policy) = expected_classification(f.finding_type);
    if !is_lowercase_uuidv7(&f.finding_id)
        || f.severity != expected_severity
        || f.policy_decision != expected_policy
        || !valid_detector(&f.detector)
        || f.evidence_refs.is_empty()
        || f.evidence_refs.len() > MAX_EVIDENCE_REFS
    {
        return Err(FindingError::invalid_field());
    }
    let mut seen = HashSet::with_capacity(f.evidence_refs.len());
    for evidence in &f.evidence_refs {
        if !is_lowercase_uuidv7(&evidence.event_id)
            || !valid_field_path(&evidence.field_path)
            || !valid_hash(&evidence.value_hash)
            || !seen.insert((
                evidence.event_id.as_str(),
                evidence.field_path.as_str(),
                evidence.value_hash.as_str(),
            ))
        {
            return Err(FindingError::invalid_field());
        }
    }
    if !valid_hash(&f.fingerprint)
        || f.fingerprint
            != fingerprint_for(FingerprintInput {
                finding_type: f.finding_type,
                severity: f.severity,
                confidence: f.confidence,
                policy_decision: f.policy_decision,
                workspace_id: &f.workspace_id,
                namespace_id: &f.namespace_id,
                detector: &f.detector,
                evidence_refs: &f.evidence_refs,
            })
    {
        return Err(FindingError::invalid_field());
    }
    Ok(())
}

pub(crate) fn expected_classification(
    finding_type: FindingType,
) -> (FindingSeverity, PolicyDecision) {
    match finding_type {
        FindingType::SecretExposure => (FindingSeverity::Critical, PolicyDecision::Deny),
        FindingType::AgentTemplateNoncompliant => {
            (FindingSeverity::High, PolicyDecision::RequireApproval)
        }
        FindingType::TelemetryIntegrity
        | FindingType::ScopeIdentityDenied
        | FindingType::UntrustedControlBoundary
        | FindingType::ToolPolicyDenied
        | FindingType::AuthAbuse
        | FindingType::AdmissionAbuse => (FindingSeverity::High, PolicyDecision::Deny),
        // An operational early-warning, not an admission decision on any one
        // event -- `Contain` reads as "operator should consider throttling
        // upstream / scaling the sink", never as "deny this request". See
        // `gateway::core::IngestGateway::record_backlog_alert`.
        FindingType::BacklogDegraded => (FindingSeverity::High, PolicyDecision::Contain),
    }
}

pub(crate) struct FingerprintInput<'a> {
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub policy_decision: PolicyDecision,
    pub workspace_id: &'a str,
    pub namespace_id: &'a str,
    pub detector: &'a str,
    pub evidence_refs: &'a [EvidenceRef],
}

pub(crate) fn fingerprint_for(input: FingerprintInput<'_>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"apex.security.finding.v3");
    for tag in [
        finding_type_tag(input.finding_type),
        severity_tag(input.severity),
        confidence_tag(input.confidence),
        policy_decision_tag(input.policy_decision),
    ] {
        update_component(&mut digest, tag.as_bytes());
    }
    for value in [input.workspace_id, input.namespace_id, input.detector] {
        update_component(&mut digest, value.as_bytes());
    }
    for evidence in input.evidence_refs {
        for value in [
            &evidence.event_id,
            &evidence.field_path,
            &evidence.value_hash,
        ] {
            update_component(&mut digest, value.as_bytes());
        }
    }
    format!("{:x}", digest.finalize())
}

fn update_component(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn finding_type_tag(value: FindingType) -> &'static str {
    match value {
        FindingType::TelemetryIntegrity => "telemetry.integrity",
        FindingType::AgentTemplateNoncompliant => "agent.template.noncompliant",
        FindingType::ScopeIdentityDenied => "identity.scope.denied",
        FindingType::UntrustedControlBoundary => "control.untrusted.boundary",
        FindingType::SecretExposure => "data.secret.exposure",
        FindingType::ToolPolicyDenied => "tool.policy.denied",
        FindingType::AuthAbuse => "auth.abuse",
        FindingType::AdmissionAbuse => "ingest.admission.abuse",
        FindingType::BacklogDegraded => "ingest.backlog.degraded",
    }
}

fn severity_tag(value: FindingSeverity) -> &'static str {
    match value {
        FindingSeverity::Info => "info",
        FindingSeverity::Low => "low",
        FindingSeverity::Medium => "medium",
        FindingSeverity::High => "high",
        FindingSeverity::Critical => "critical",
    }
}

fn confidence_tag(value: FindingConfidence) -> &'static str {
    match value {
        FindingConfidence::Deterministic => "deterministic",
        FindingConfidence::Corroborated => "corroborated",
        FindingConfidence::Heuristic => "heuristic",
    }
}

fn policy_decision_tag(value: PolicyDecision) -> &'static str {
    match value {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Deny => "deny",
        PolicyDecision::RequireApproval => "require_approval",
        PolicyDecision::Contain => "contain",
    }
}

pub(crate) fn valid_detector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

pub(crate) fn logically_equal(left: &SecurityFinding, right: &SecurityFinding) -> bool {
    left.finding_type == right.finding_type
        && left.severity == right.severity
        && left.confidence == right.confidence
        && left.workspace_id == right.workspace_id
        && left.namespace_id == right.namespace_id
        && left.detector == right.detector
        && left.evidence_refs == right.evidence_refs
        && left.policy_decision == right.policy_decision
        && left.fingerprint == right.fingerprint
}

pub(crate) fn validate_scope(workspace: &str, namespace: &str) -> Result<(), FindingError> {
    if is_scope_identifier(workspace) && is_scope_identifier(namespace) {
        Ok(())
    } else {
        Err(FindingError::invalid_field())
    }
}

pub(crate) fn valid_actor_scope(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_ACTOR_SCOPE_BYTES
        || !value.is_ascii()
        || value.chars().any(|character| character.is_control())
    {
        return false;
    }
    let Some((workspace, namespace)) = value.split_once('/') else {
        return false;
    };
    validate_scope(workspace, namespace).is_ok()
}

pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(crate) fn valid_field_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

pub(crate) fn allowed_transition(from: FindingStatus, to: FindingStatus) -> bool {
    matches!(
        (from, to),
        (
            FindingStatus::Open,
            FindingStatus::Acknowledged | FindingStatus::Contained | FindingStatus::FalsePositive
        ) | (
            FindingStatus::Acknowledged,
            FindingStatus::Contained | FindingStatus::Resolved | FindingStatus::FalsePositive
        ) | (FindingStatus::Contained, FindingStatus::Resolved)
    )
}
