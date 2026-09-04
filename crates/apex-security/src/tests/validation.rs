// Security finding tests for validation responsibilities.

#[test]
fn rejects_unsafe_evidence_and_scope() {
    assert!(EvidenceRef::new(EVENT, "data..raw", HASH).is_err());
    assert!(EvidenceRef::new(EVENT, "data.raw", &HASH.to_ascii_uppercase()).is_err());
    assert!(
        new_finding(FindingInput {
            finding_type: FindingType::ToolPolicyDenied,
            severity: FindingSeverity::High,
            confidence: FindingConfidence::Deterministic,
            workspace_id: "../acme".to_owned(),
            namespace_id: "prod".to_owned(),
            detector: "detector".to_owned(),
            evidence_refs: vec![],
            policy_decision: PolicyDecision::Deny,
        })
        .is_err()
    );
}

#[test]
fn rejects_duplicate_evidence_references() {
    let evidence = EvidenceRef::new(EVENT, "data.secret_hash", HASH).unwrap();
    assert_eq!(
        new_finding(FindingInput {
            finding_type: FindingType::SecretExposure,
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::Deterministic,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            detector: "duplicate-evidence-test".to_owned(),
            evidence_refs: vec![evidence.clone(), evidence],
            policy_decision: PolicyDecision::Deny,
        })
        .unwrap_err()
        .code,
        FindingErrorCode::InvalidField
    );
}

#[test]
fn validates_bounded_detector_and_evidence_collections() {
    let base = || FindingInput {
        finding_type: FindingType::TelemetryIntegrity,
        severity: FindingSeverity::High,
        confidence: FindingConfidence::Corroborated,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        detector: "detector".to_owned(),
        evidence_refs: vec![],
        policy_decision: PolicyDecision::Deny,
    };
    let mut input = base();
    input.detector = "bad detector".to_owned();
    assert_eq!(
        new_finding(input).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
    let input = base();
    assert_eq!(
        new_finding(input).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
    let mut input = base();
    input.evidence_refs = (0..=MAX_EVIDENCE_REFS)
        .map(|_| EvidenceRef::new(EVENT, "data.hash", HASH).unwrap())
        .collect();
    assert_eq!(
        new_finding(input).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
    assert!(FindingStore::new(MAX_FINDINGS + 1).is_err());
    assert!(
        FindingError::invalid_field()
            .to_string()
            .contains("INVALID_SECURITY_FINDING_FIELD")
    );
    for error in [
        FindingError::capacity(),
        FindingError::duplicate_id(),
        FindingError::fingerprint_conflict(),
        FindingError::not_found(),
        FindingError::scope_denied(),
        FindingError::invalid_transition(),
        FindingError::entropy_unavailable(),
        FindingError::clock_unavailable(),
    ] {
        assert!(!error.code.as_str().is_empty());
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn rejects_invalid_finding_records_and_evidence_paths() {
    assert!(EvidenceRef::new(EVENT, "", HASH).is_err());
    assert!(EvidenceRef::new(EVENT, &"x".repeat(257), HASH).is_err());
    assert!(EvidenceRef::new(EVENT, "data raw", HASH).is_err());
    let mut record = finding("record");
    record.finding_id = "not-a-uuid".to_owned();
    let mut store = FindingStore::new(1).unwrap();
    assert_eq!(
        store.append(record).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
}

#[test]
fn empty_error_guidance_is_display_safe() {
    let error = FindingError {
        code: FindingErrorCode::InvalidField,
        summary: "summary",
        cause: "cause",
        retryable: false,
        next_steps: &[],
    };
    assert!(error.to_string().contains("No remediation guidance"));
}

// UUID generation coverage lives in tests_ids.rs.
