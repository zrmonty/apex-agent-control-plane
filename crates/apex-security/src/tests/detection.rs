// Security finding tests for detection responsibilities.

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
        SecuritySignal::BacklogDegraded,
    ];
    let mut store = FindingStore::new(signals.len()).unwrap();
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
