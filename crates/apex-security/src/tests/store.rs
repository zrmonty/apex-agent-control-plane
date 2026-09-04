// Security finding tests for store responsibilities.

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
    let unauthorized = crate::Caller::authenticated_for_agent(
        "spiffe://apex/other",
        "other-agent",
        ["other/prod"],
    )
    .unwrap();
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
    let other_caller = crate::Caller::authenticated_for_agent(
        "spiffe://apex/other",
        "other-agent",
        ["other/prod"],
    )
    .unwrap();
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
