use super::journal::{FindingJournal, MAX_JOURNAL_BYTES};
use super::*;
use crate::security::{
    ContainmentAction, DetectionInput, FindingStatus, FindingStore, SecurityFinding,
    SecuritySignal, detect_and_record,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
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
    finding_with_event_id("018f5f2a-7b00-7000-8000-000000000001")
}

fn finding_with_event_id(event_id: &str) -> SecurityFinding {
    let mut store = FindingStore::new(4).expect("test store capacity is valid");
    detect_and_record(
        &mut store,
        DetectionInput {
            signal: SecuritySignal::SecretExposure,
            workspace_id: "workspace-1".into(),
            namespace_id: "namespace-1".into(),
            event_id: event_id.into(),
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

/// A trailing write torn by a crash mid-write/before `sync_data()` returned
/// must not be indistinguishable from real corruption: it was never
/// acknowledged to any caller (the `append`/`transition` that produced it
/// returned an error, or never returned, before the crash), so it is always
/// safe to discard. The journal must load successfully, keep every record
/// that parsed cleanly before the torn tail, and self-heal by truncating the
/// torn bytes off the file.
#[test]
fn journal_recovers_from_a_torn_trailing_record() {
    let root = test_root("torn-trailing");
    let path = root.join("findings.jsonl");
    let item = finding();
    {
        let mut journal = FindingJournal::open(&path, &root, 4).expect("journal opens");
        assert!(journal.append(item.clone()).expect("append succeeds"));
    }
    let good_len = fs::metadata(&path).unwrap().len();

    // Produce a second record's exact on-disk bytes by writing it through the
    // same code path into a scratch journal (rather than hand-encoding the
    // journal's private record format), then simulate a crash mid-write by
    // copying only half of those bytes — with no trailing newline — into the
    // real journal file.
    let scratch_root = test_root("torn-trailing-scratch");
    let scratch_path = scratch_root.join("findings.jsonl");
    {
        let mut scratch =
            FindingJournal::open(&scratch_path, &scratch_root, 4).expect("scratch journal opens");
        assert!(
            scratch
                .append(finding_with_event_id(
                    "018f5f2a-7b00-7000-8000-000000000002"
                ))
                .expect("scratch append succeeds")
        );
    }
    let full_line_bytes = fs::read(&scratch_path).expect("scratch journal readable");
    let torn_prefix = &full_line_bytes[..full_line_bytes.len() / 2];
    {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(torn_prefix).unwrap();
    }

    let reopened = FindingJournal::open(&path, &root, 4)
        .expect("a torn trailing record must not permanently block the journal from loading");
    let listed = reopened
        .store()
        .findings_for_scope(&caller(), "workspace-1", "namespace-1")
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], &item);

    // Self-healing: the torn fragment was truncated off on load, so the file
    // is back to exactly the last known-good state.
    assert_eq!(fs::metadata(&path).unwrap().len(), good_len);

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(scratch_root);
}

/// A malformed record in the MIDDLE of the file — even with a good record
/// after it — must keep failing closed exactly as before. Guessing at intent
/// there would risk silently dropping committed state.
#[test]
fn journal_still_fails_closed_on_a_corrupt_middle_record_with_a_good_record_after_it() {
    let root = test_root("corrupt-middle");
    let path = root.join("findings.jsonl");
    let item = finding();
    {
        let mut journal = FindingJournal::open(&path, &root, 4).expect("journal opens");
        assert!(journal.append(item).expect("append succeeds"));
    }

    // Produce a second good record's exact on-disk line via the same code
    // path (through a scratch journal), so this test does not depend on the
    // journal's private serialization format.
    let scratch_root = test_root("corrupt-middle-scratch");
    let scratch_path = scratch_root.join("findings.jsonl");
    let trailing_line = {
        let mut scratch =
            FindingJournal::open(&scratch_path, &scratch_root, 4).expect("scratch journal opens");
        assert!(
            scratch
                .append(finding_with_event_id(
                    "018f5f2a-7b00-7000-8000-000000000002"
                ))
                .expect("scratch append succeeds")
        );
        fs::read_to_string(&scratch_path).expect("scratch journal readable")
    };

    {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"not-json\n").unwrap();
        file.write_all(trailing_line.as_bytes()).unwrap();
    }

    let error = FindingJournal::open(&path, &root, 4)
        .expect_err("a malformed record in the middle of the file must still fail closed");
    assert_eq!(error.code(), "SECURITY_FINDING_JOURNAL_RECORD_INVALID");

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(scratch_root);
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
