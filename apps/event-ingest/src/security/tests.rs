use super::detect::new_finding;
use super::ids::uuid7;
use super::types::FindingInput;
use super::validate::MAX_EVIDENCE_REFS;
use super::validate::MAX_FINDINGS;
use super::*;
use crate::is_lowercase_uuidv7;

const EVENT: &str = "018f5c91-2d88-7c00-8000-000000000001";
const HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

fn caller() -> crate::Caller {
    crate::Caller::authenticated("spiffe://apex/security-test", ["acme/prod"])
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

#[test]
fn creates_redacted_finding_and_scopes_reads() {
    let mut store = FindingStore::new(2).unwrap();
    assert!(store.append(finding("secret-detector")).unwrap());
    assert_eq!(
        store
            .findings_for_scope(&caller(), "acme", "prod")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .findings_for_scope(&caller(), "other", "prod")
            .unwrap_err()
            .code,
        FindingErrorCode::ScopeDenied
    );
    let debug = format!("{store:?}");
    assert!(!debug.contains("secret-detector"));
}

#[test]
fn deduplicates_same_fingerprint_without_overwriting() {
    let mut store = FindingStore::new(2).unwrap();
    let first = finding("same");
    let mut second = first.clone();
    second.finding_id = uuid7().unwrap();
    assert!(store.append(first).unwrap());
    assert!(!store.append(second).unwrap());
    assert_eq!(
        store
            .findings_for_scope(&caller(), "acme", "prod")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn rejects_changed_duplicate_id() {
    let mut store = FindingStore::new(2).unwrap();
    let first = finding("one");
    let mut second = first.clone();
    second.severity = FindingSeverity::High;
    assert!(store.append(first).unwrap());
    assert_eq!(
        store.append(second).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
}

#[test]
fn rejects_fingerprint_downgrade_and_public_record_bypass() {
    let mut store = FindingStore::new(2).unwrap();
    let first = finding("same-signal");
    let mut changed = first.clone();
    changed.finding_id = uuid7().unwrap();
    changed.severity = FindingSeverity::Low;
    assert!(store.append(first).unwrap());
    assert_eq!(
        store.append(changed).unwrap_err().code,
        FindingErrorCode::InvalidField
    );

    let mut unsafe_record = finding("safe");
    unsafe_record.finding_id = uuid7().unwrap();
    unsafe_record.detector = "unsafe detector".to_owned();
    assert_eq!(
        store.append(unsafe_record).unwrap_err().code,
        FindingErrorCode::InvalidField
    );

    let mut forged_fingerprint = finding("forged");
    forged_fingerprint.finding_id = uuid7().unwrap();
    forged_fingerprint.fingerprint = "a".repeat(64);
    assert_eq!(
        store.append(forged_fingerprint).unwrap_err().code,
        FindingErrorCode::InvalidField
    );

    let mut wrong_policy = finding("wrong-policy");
    wrong_policy.finding_id = uuid7().unwrap();
    wrong_policy.policy_decision = PolicyDecision::Allow;
    assert_eq!(
        store.append(wrong_policy).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
}

#[test]
fn transitions_are_append_only_and_scope_checked() {
    let mut store = FindingStore::new(2).unwrap();
    let f = finding("transition");
    let id = f.finding_id.clone();
    store.append(f).unwrap();
    let unauthorized = crate::Caller::authenticated("spiffe://apex/other", ["other/prod"]);
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Acknowledged,
                &unauthorized,
                "acme/prod",
                None,
            )
            .unwrap_err()
            .code,
        FindingErrorCode::ScopeDenied
    );
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Acknowledged,
                &caller(),
                &format!("acme/{}", "x".repeat(256)),
                None,
            )
            .unwrap_err()
            .code,
        FindingErrorCode::ScopeDenied
    );
    store
        .transition(
            &id,
            FindingStatus::Open,
            FindingStatus::Contained,
            &caller(),
            "acme/prod",
            Some(ContainmentAction::Pause),
        )
        .unwrap();
    assert_eq!(store.current_status(&id).unwrap(), FindingStatus::Contained);
    assert_eq!(
        store.findings_for_scope(&caller(), "acme", "prod").unwrap()[0].finding_id,
        id
    );
    assert_eq!(store.updates().len(), 1);
    let updates = store.updates_for_scope(&caller(), "acme", "prod").unwrap();
    assert_eq!(updates[0].actor_subject, "spiffe://apex/security-test");
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Contained,
                FindingStatus::Open,
                &caller(),
                "acme/prod",
                None
            )
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidTransition
    );
}

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
fn capacity_and_not_found_errors_are_actionable() {
    assert_eq!(
        FindingStore::new(0).unwrap_err().code,
        FindingErrorCode::Capacity
    );
    let mut store = FindingStore::new(1).unwrap();
    store.append(finding("capacity")).unwrap();
    assert_eq!(
        store.append(finding("other")).unwrap_err().code,
        FindingErrorCode::Capacity
    );
    assert_eq!(
        store
            .transition(
                EVENT,
                FindingStatus::Open,
                FindingStatus::Acknowledged,
                &caller(),
                "acme/prod",
                None
            )
            .unwrap_err()
            .code,
        FindingErrorCode::NotFound
    );
    assert_eq!(
        store.current_status(EVENT).unwrap_err().code,
        FindingErrorCode::NotFound
    );
}

#[test]
fn capacity_isolated_per_scope_with_global_hard_cap() {
    let mut store = FindingStore::new(1).unwrap();
    store
        .append(finding("tenant-a"))
        .expect("first tenant may use its quota");
    store
        .append(scoped_finding("tenant-b", "other", "prod"))
        .expect("another tenant must not be blocked by the first tenant");
    assert_eq!(
        store.append(finding("tenant-a-again")).unwrap_err().code,
        FindingErrorCode::Capacity
    );

    let mut bounded = FindingStore::with_quotas(2, 2).unwrap();
    bounded.append(finding("global-a")).unwrap();
    bounded
        .append(scoped_finding("global-b", "other", "prod"))
        .unwrap();
    assert_eq!(
        bounded
            .append(scoped_finding("global-c", "third", "prod"))
            .unwrap_err()
            .code,
        FindingErrorCode::Capacity
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
fn enforces_scope_and_allowlisted_status_transitions() {
    let mut store = FindingStore::new(8).unwrap();
    let record = finding("status");
    let id = record.finding_id.clone();
    store.append(record).unwrap();
    assert_eq!(
        store
            .findings_for_scope(&caller(), "bad scope", "prod")
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidField
    );
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Acknowledged,
                &caller(),
                "other/prod",
                None
            )
            .unwrap_err()
            .code,
        FindingErrorCode::ScopeDenied
    );
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Contained,
                &caller(),
                "acme/prod",
                None
            )
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidTransition
    );
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Resolved,
                &caller(),
                "acme/prod",
                Some(ContainmentAction::DisableTool),
            )
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidTransition
    );
    store
        .transition(
            &id,
            FindingStatus::Open,
            FindingStatus::Acknowledged,
            &caller(),
            "acme/prod",
            None,
        )
        .unwrap();
    store
        .transition(
            &id,
            FindingStatus::Acknowledged,
            FindingStatus::Contained,
            &caller(),
            "acme/prod",
            Some(ContainmentAction::Quarantine),
        )
        .unwrap();
    assert_eq!(
        store
            .transition(
                &id,
                FindingStatus::Contained,
                FindingStatus::Resolved,
                &caller(),
                "acme/prod",
                None,
            )
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidTransition
    );
    store
        .transition(
            &id,
            FindingStatus::Contained,
            FindingStatus::Resolved,
            &caller(),
            "acme/prod",
            Some(ContainmentAction::DisableTool),
        )
        .unwrap();
    assert_eq!(store.current_status(&id).unwrap(), FindingStatus::Resolved);
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
fn deterministic_detector_maps_each_signal_to_redacted_findings() {
    let signals = [
        SecuritySignal::TelemetryIntegrity,
        SecuritySignal::ScopeIdentityDenied,
        SecuritySignal::UntrustedControlBoundary,
        SecuritySignal::SecretExposure,
        SecuritySignal::ToolPolicyDenied,
        SecuritySignal::AgentTemplateNoncompliant,
        SecuritySignal::AuthAbuse,
        SecuritySignal::AdmissionAbuse,
    ];
    let mut store = FindingStore::new(8).unwrap();
    for (index, signal) in signals.into_iter().enumerate() {
        assert!(
            detect_and_record(
                &mut store,
                DetectionInput {
                    signal,
                    workspace_id: "acme".to_owned(),
                    namespace_id: "prod".to_owned(),
                    event_id: EVENT.to_owned(),
                    field_path: format!("data.signal_{index}"),
                    value_hash: HASH.to_owned(),
                },
            )
            .unwrap()
        );
    }
    assert_eq!(
        store
            .findings_for_scope(&caller(), "acme", "prod")
            .unwrap()
            .len(),
        signals.len()
    );
    assert_eq!(
        store.findings_for_scope(&caller(), "acme", "prod").unwrap()[3].severity,
        FindingSeverity::Critical
    );
    assert_eq!(
        store.findings_for_scope(&caller(), "acme", "prod").unwrap()[5].policy_decision,
        PolicyDecision::RequireApproval
    );
    assert!(
        !detect_and_record(
            &mut store,
            DetectionInput {
                signal: SecuritySignal::SecretExposure,
                workspace_id: "acme".to_owned(),
                namespace_id: "prod".to_owned(),
                event_id: EVENT.to_owned(),
                field_path: "data.signal_3".to_owned(),
                value_hash: HASH.to_owned(),
            },
        )
        .unwrap()
    );
}

#[test]
fn detector_rejects_untrusted_or_cross_scope_inputs_before_storage() {
    let mut store = FindingStore::new(2).unwrap();
    let mut input = DetectionInput {
        signal: SecuritySignal::SecretExposure,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        event_id: EVENT.to_owned(),
        field_path: "data.secret".to_owned(),
        value_hash: HASH.to_owned(),
    };
    input.value_hash = HASH.to_ascii_uppercase();
    assert_eq!(
        detect_and_record(&mut store, input.clone())
            .unwrap_err()
            .code,
        FindingErrorCode::InvalidField
    );
    input.value_hash = HASH.to_owned();
    input.workspace_id = "../acme".to_owned();
    assert_eq!(
        detect_and_record(&mut store, input).unwrap_err().code,
        FindingErrorCode::InvalidField
    );
    assert!(
        store
            .findings_for_scope(&caller(), "acme", "prod")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn findings_for_scope_filters_without_cross_scope_leakage() {
    let mut store = FindingStore::new(4).unwrap();
    store.append(finding("scope-a")).unwrap();
    let scoped = store.findings_for_scope(&caller(), "acme", "prod").unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].workspace_id, "acme");
    assert_eq!(
        store
            .findings_for_scope(&caller(), "other", "prod")
            .unwrap_err()
            .code,
        FindingErrorCode::ScopeDenied
    );
    let other_caller = crate::Caller::authenticated("spiffe://apex/other", ["other/prod"]);
    assert!(
        store
            .findings_for_scope(&other_caller, "other", "prod")
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .findings_for_scope(&caller(), "../acme", "prod")
            .is_err()
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

#[test]
fn generated_finding_ids_are_uuidv7_and_unique_for_a_burst() {
    let first = uuid7().unwrap();
    let second = uuid7().unwrap();
    assert!(is_lowercase_uuidv7(&first));
    assert!(is_lowercase_uuidv7(&second));
    assert_ne!(first, second);
}
