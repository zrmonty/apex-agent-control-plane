use super::error::FindingError;
use super::ids::{now_ms, uuid7};
use super::store::FindingStore;
use super::types::{
    DetectionInput, EvidenceRef, FindingConfidence, FindingInput, FindingSeverity, FindingType,
    PolicyDecision, SecurityFinding, SecuritySignal,
};
use super::validate::{
    FingerprintInput, MAX_EVIDENCE_REFS, fingerprint_for, valid_detector, validate_finding,
    validate_scope,
};

pub(crate) fn new_finding(input: FindingInput) -> Result<SecurityFinding, FindingError> {
    validate_scope(&input.workspace_id, &input.namespace_id)?;
    if !valid_detector(&input.detector)
        || input.evidence_refs.is_empty()
        || input.evidence_refs.len() > MAX_EVIDENCE_REFS
    {
        return Err(FindingError::invalid_field());
    }
    let fingerprint = fingerprint_for(FingerprintInput {
        finding_type: input.finding_type,
        severity: input.severity,
        confidence: input.confidence,
        policy_decision: input.policy_decision,
        workspace_id: &input.workspace_id,
        namespace_id: &input.namespace_id,
        detector: &input.detector,
        evidence_refs: &input.evidence_refs,
    });
    let finding = SecurityFinding {
        finding_id: uuid7()?,
        finding_type: input.finding_type,
        severity: input.severity,
        confidence: input.confidence,
        workspace_id: input.workspace_id,
        namespace_id: input.namespace_id,
        detector: input.detector,
        evidence_refs: input.evidence_refs,
        policy_decision: input.policy_decision,
        fingerprint,
        created_at_ms: now_ms()?,
    };
    validate_finding(&finding)?;
    Ok(finding)
}

/// Convert one trusted, redacted boundary signal into an immutable finding.
/// The store remains the authoritative deduplication and scope boundary.
pub fn detect_and_record(
    store: &mut FindingStore,
    input: DetectionInput,
) -> Result<bool, FindingError> {
    store.append(detection_finding(input)?)
}

pub fn detection_finding(input: DetectionInput) -> Result<SecurityFinding, FindingError> {
    let (finding_type, severity, policy_decision, detector) = match input.signal {
        SecuritySignal::TelemetryIntegrity => (
            FindingType::TelemetryIntegrity,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "telemetry.integrity.v1",
        ),
        SecuritySignal::ScopeIdentityDenied => (
            FindingType::ScopeIdentityDenied,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "identity.scope-denied.v1",
        ),
        SecuritySignal::UntrustedControlBoundary => (
            FindingType::UntrustedControlBoundary,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "control.untrusted-boundary.v1",
        ),
        SecuritySignal::SecretExposure => (
            FindingType::SecretExposure,
            FindingSeverity::Critical,
            PolicyDecision::Deny,
            "data.secret-exposure.v1",
        ),
        SecuritySignal::ToolPolicyDenied => (
            FindingType::ToolPolicyDenied,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "tool.policy-denied.v1",
        ),
        SecuritySignal::AgentTemplateNoncompliant => (
            FindingType::AgentTemplateNoncompliant,
            FindingSeverity::High,
            PolicyDecision::RequireApproval,
            "agent.template-noncompliant.v1",
        ),
        SecuritySignal::AuthAbuse => (
            FindingType::AuthAbuse,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "auth.abuse-rate-limit.v1",
        ),
        SecuritySignal::AdmissionAbuse => (
            FindingType::AdmissionAbuse,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "ingest.admission-abuse.v1",
        ),
        SecuritySignal::BacklogDegraded => (
            FindingType::BacklogDegraded,
            FindingSeverity::High,
            PolicyDecision::Contain,
            "ingest.backlog-degraded.v1",
        ),
    };
    let evidence = EvidenceRef::new(&input.event_id, &input.field_path, &input.value_hash)?;
    new_finding(FindingInput {
        finding_type,
        severity,
        confidence: FindingConfidence::Deterministic,
        workspace_id: input.workspace_id,
        namespace_id: input.namespace_id,
        detector: detector.to_owned(),
        evidence_refs: vec![evidence],
        policy_decision,
    })
}

