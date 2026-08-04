use super::journal::{FindingJournal, MAX_JOURNAL_BYTES};
use super::*;
use crate::security::{
    ContainmentAction, DetectionInput, FindingStatus, FindingStore, SecurityFinding,
    SecuritySignal, detect_and_record,
};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn test_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("apex-finding-journal-{label}-{nonce}"));
    fs::create_dir_all(&root).expect("test journal directory must be creatable");
    root
}

fn caller() -> crate::Caller {
    crate::Caller::authenticated("spiffe://apex/journal-tests", ["workspace-1/namespace-1"])
}

fn finding() -> SecurityFinding {
    let mut store = FindingStore::new(4).expect("test store capacity is valid");
    detect_and_record(
        &mut store,
        DetectionInput {
            signal: SecuritySignal::SecretExposure,
            workspace_id: "workspace-1".into(),
            namespace_id: "namespace-1".into(),
            event_id: "018f5f2a-7b00-7000-8000-000000000001".into(),
            field_path: "event.payload".into(),
            value_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        },
    )
    .expect("detector should create a valid finding");
    store
        .findings_for_scope(&caller(), "workspace-1", "namespace-1")
        .unwrap()[0]
        .clone()
}

#[test]
fn restart_replays_findings_and_status_updates() {
    let root = test_root("restart");
    let path = root.join("findings.jsonl");
    let item = finding();
    {
        let mut journal = FindingJournal::open(&path, &root, 4).expect("journal opens");
        assert!(journal.path().ends_with("findings.jsonl"));
        assert!(journal.append(item.clone()).expect("append succeeds"));
        assert!(
            !journal
                .append(item.clone())
                .expect("duplicate replay is safe")
        );
        journal
            .transition(
                &item.finding_id,
                FindingStatus::Open,
                FindingStatus::Contained,
                &crate::Caller::authenticated(
                    "spiffe://apex/journal-test",
                    ["workspace-1/namespace-1"],
                ),
                "workspace-1/namespace-1",
                Some(ContainmentAction::Quarantine),
            )
            .expect("status update persists");
    }
    let reopened = FindingJournal::open(&path, &root, 4).expect("journal reopens");
    let listed = reopened
        .store()
        .findings_for_scope(&caller(), "workspace-1", "namespace-1")
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], &item);
    assert_eq!(
        reopened.store().current_status(&item.finding_id).unwrap(),
        FindingStatus::Contained
    );
    assert_eq!(reopened.store().updates().len(), 1);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rejects_relative_and_out_of_boundary_paths() {
    let root = test_root("paths");
    assert!(matches!(
        FindingJournal::open(Path::new("findings.jsonl"), &root, 4),
        Err(FindingPersistenceError::InvalidPath)
    ));
    let outside = root
        .parent()
        .expect("temp root has parent")
        .join("outside.jsonl");
    assert!(matches!(
        FindingJournal::open(&outside, &root, 4),
        Err(FindingPersistenceError::InvalidPath)
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn malformed_record_is_rejected_with_diagnostic_code() {
    let root = test_root("malformed");
    let path = root.join("findings.jsonl");
    fs::write(&path, b"not-json\n").expect("test journal can be written");
    let error = FindingJournal::open(&path, &root, 4).expect_err("malformed record rejected");
    assert_eq!(error.code(), "SECURITY_FINDING_JOURNAL_RECORD_INVALID");
    assert!(error.to_string().contains("first malformed line"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn persistence_error_codes_and_display_are_actionable() {
    for error in [
        FindingPersistenceError::Io,
        FindingPersistenceError::InvalidPath,
        FindingPersistenceError::OversizedJournal,
        FindingPersistenceError::MalformedRecord,
    ] {
        assert!(!error.code().is_empty());
        assert!(error.to_string().contains("Cause:"));
        assert!(error.to_string().contains("Next:"));
    }
    let store_err = FindingPersistenceError::Store(crate::security::FindingError::invalid_field());
    assert_eq!(store_err.code(), "SECURITY_FINDING_JOURNAL_STORE_REJECTED");
    assert!(store_err.to_string().contains("persistence rejected"));
}

#[test]
fn append_refuses_to_cross_journal_size_limit() {
    let root = test_root("size-limit");
    let path = root.join("findings.jsonl");
    let item = finding();
    let mut journal = FindingJournal::open(&path, &root, 4).expect("journal opens");
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("test file can be opened");
    file.set_len(MAX_JOURNAL_BYTES - 1)
        .expect("test file can be expanded");
    let error = journal
        .append(item)
        .expect_err("append must remain inside the journal bound");
    assert!(matches!(error, FindingPersistenceError::OversizedJournal));
    assert!(
        journal
            .store()
            .findings_for_scope(&caller(), "workspace-1", "namespace-1")
            .unwrap()
            .is_empty()
    );
    let _ = fs::remove_dir_all(root);
}
