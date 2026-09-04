use super::detect::new_finding;
use super::ids::uuid7;
use super::types::FindingInput;
use super::validate::MAX_EVIDENCE_REFS;
use super::validate::MAX_FINDINGS;
use super::*;

const EVENT: &str = "018f5c91-2d88-7c00-8000-000000000001";
const HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

fn caller() -> crate::Caller {
    crate::Caller::authenticated_for_agent(
        "spiffe://apex/security-test",
        "security-agent",
        ["acme/prod"],
    )
    .unwrap()
}

fn scoped_finding(detector: &str, workspace_id: &str, namespace_id: &str) -> SecurityFinding {
    new_finding(FindingInput {
        finding_type: FindingType::SecretExposure,
        severity: FindingSeverity::Critical,
        confidence: FindingConfidence::Deterministic,
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        detector: detector.to_owned(),
        evidence_refs: vec![EvidenceRef::new(EVENT, "data.secret_hash", HASH).unwrap()],
        policy_decision: PolicyDecision::Deny,
    })
    .unwrap()
}

fn finding(detector: &str) -> SecurityFinding {
    scoped_finding(detector, "acme", "prod")
}

include!("tests/store.rs");
include!("tests/validation.rs");
include!("tests/detection.rs");
