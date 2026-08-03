use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::security::{
    ContainmentAction, FindingError, FindingStatus, FindingStatusUpdate, FindingStore,
    SecurityFinding,
};

const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
enum JournalRecord {
    Finding(SecurityFinding),
    Status(FindingStatusUpdate),
}

/// Single-writer, append-only local journal. Callers must serialize access to
/// one path at the process/deployment level; this seam is not a multi-writer
/// database and intentionally has no distributed locking protocol.
#[derive(Debug)]
pub struct FindingJournal {
    path: PathBuf,
    writer: BufWriter<File>,
    store: FindingStore,
}

#[derive(Debug)]
pub enum FindingPersistenceError {
    Io,
    InvalidPath,
    OversizedJournal,
    MalformedRecord,
    Store(FindingError),
}

impl FindingPersistenceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io => "SECURITY_FINDING_JOURNAL_IO",
            Self::InvalidPath => "SECURITY_FINDING_JOURNAL_PATH_INVALID",
            Self::OversizedJournal => "SECURITY_FINDING_JOURNAL_TOO_LARGE",
            Self::MalformedRecord => "SECURITY_FINDING_JOURNAL_RECORD_INVALID",
            Self::Store(_) => "SECURITY_FINDING_JOURNAL_STORE_REJECTED",
        }
    }
}

impl std::fmt::Display for FindingPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (summary, cause, next) = match self {
            Self::Io => (
                "The security finding journal could not be read or durably written.",
                "The filesystem returned an I/O failure while opening, replaying, or syncing the journal.",
                "Check the path, permissions, disk health, and available space before retrying.",
            ),
            Self::InvalidPath => (
                "The security finding journal path is outside the trusted persistence boundary.",
                "The base or journal path is missing, symlinked, non-directory, relative, or escapes the configured base.",
                "Use an absolute regular-file path inside the configured trusted base directory.",
            ),
            Self::OversizedJournal => (
                "The security finding journal exceeds a configured safety limit.",
                "The journal or one record is larger than the bounded replay limits.",
                "Rotate or archive the journal through the retention workflow, then retry with a bounded file.",
            ),
            Self::MalformedRecord => (
                "The security finding journal contains an invalid record.",
                "A JSONL record could not be decoded or serialized without violating the finding contract.",
                "Quarantine the journal, identify the first malformed line, and restore from a trusted immutable copy.",
            ),
            Self::Store(error) => {
                return write!(
                    f,
                    "{}: persistence rejected the finding. Cause: {}",
                    self.code(),
                    error
                );
            }
        };
        write!(
            f,
            "{}: {} Cause: {} Next: {}",
            self.code(),
            summary,
            cause,
            next
        )
    }
}

impl std::error::Error for FindingPersistenceError {}

impl FindingJournal {
    pub fn open(
        path: &Path,
        trusted_base: &Path,
        capacity: usize,
    ) -> Result<Self, FindingPersistenceError> {
        if !path.is_absolute() || !trusted_base.is_absolute() {
            return Err(FindingPersistenceError::InvalidPath);
        }
        let base = trusted_base
            .canonicalize()
            .map_err(|_| FindingPersistenceError::InvalidPath)?;
        if !base.is_dir() || trusted_base.is_symlink() || path.is_symlink() {
            return Err(FindingPersistenceError::InvalidPath);
        }
        let parent = path.parent().ok_or(FindingPersistenceError::InvalidPath)?;
        let parent = parent
            .canonicalize()
            .map_err(|_| FindingPersistenceError::InvalidPath)?;
        if !parent.starts_with(&base) {
            return Err(FindingPersistenceError::InvalidPath);
        }
        let resolved = parent.join(
            path.file_name()
                .ok_or(FindingPersistenceError::InvalidPath)?,
        );
        if resolved.exists()
            && fs::symlink_metadata(&resolved)
                .map_err(|_| FindingPersistenceError::Io)?
                .file_type()
                .is_symlink()
        {
            return Err(FindingPersistenceError::InvalidPath);
        }
        if resolved.exists() && !resolved.is_file() {
            return Err(FindingPersistenceError::InvalidPath);
        }
        if resolved.exists()
            && fs::metadata(&resolved)
                .map_err(|_| FindingPersistenceError::Io)?
                .len()
                > MAX_JOURNAL_BYTES
        {
            return Err(FindingPersistenceError::OversizedJournal);
        }
        let mut store = FindingStore::new(capacity).map_err(FindingPersistenceError::Store)?;
        if resolved.exists() {
            let reader =
                BufReader::new(File::open(&resolved).map_err(|_| FindingPersistenceError::Io)?);
            let mut replayed_bytes = 0_u64;
            for line in reader.lines() {
                let line = line.map_err(|_| FindingPersistenceError::Io)?;
                replayed_bytes = replayed_bytes
                    .saturating_add(line.len() as u64)
                    .saturating_add(1);
                if replayed_bytes > MAX_JOURNAL_BYTES {
                    return Err(FindingPersistenceError::OversizedJournal);
                }
                if line.len() > MAX_JOURNAL_LINE_BYTES {
                    return Err(FindingPersistenceError::OversizedJournal);
                }
                let record: JournalRecord = serde_json::from_str(&line)
                    .map_err(|_| FindingPersistenceError::MalformedRecord)?;
                match record {
                    JournalRecord::Finding(finding) => {
                        store
                            .append(finding)
                            .map_err(FindingPersistenceError::Store)?;
                    }
                    JournalRecord::Status(update) => {
                        store
                            .transition(
                                &update.finding_id,
                                update.from,
                                update.to,
                                &update.actor_scope,
                                update.action,
                            )
                            .map_err(FindingPersistenceError::Store)?;
                    }
                }
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&resolved)
            .map_err(|_| FindingPersistenceError::Io)?;
        // Re-check after opening to catch a path replacement between the
        // initial boundary checks and the filesystem open operation.
        let metadata = fs::symlink_metadata(&resolved).map_err(|_| FindingPersistenceError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(FindingPersistenceError::InvalidPath);
        }
        let writer = BufWriter::new(file);
        Ok(Self {
            path: resolved,
            writer,
            store,
        })
    }

    pub fn store(&self) -> &FindingStore {
        &self.store
    }

    pub fn append(&mut self, finding: SecurityFinding) -> Result<bool, FindingPersistenceError> {
        let before = self.store.clone();
        let accepted = self
            .store
            .append(finding.clone())
            .map_err(FindingPersistenceError::Store)?;
        if accepted && let Err(error) = self.write_record(&JournalRecord::Finding(finding)) {
            self.store = before;
            return Err(error);
        }
        Ok(accepted)
    }

    pub fn transition(
        &mut self,
        finding_id: &str,
        expected: FindingStatus,
        to: FindingStatus,
        actor_scope: &str,
        action: Option<ContainmentAction>,
    ) -> Result<(), FindingPersistenceError> {
        let before = self.store.clone();
        self.store
            .transition(finding_id, expected, to, actor_scope, action)
            .map_err(FindingPersistenceError::Store)?;
        let update = self
            .store
            .updates()
            .last()
            .cloned()
            .ok_or(FindingPersistenceError::MalformedRecord)?;
        if let Err(error) = self.write_record(&JournalRecord::Status(update)) {
            self.store = before;
            return Err(error);
        }
        Ok(())
    }

    fn write_record(&mut self, record: &JournalRecord) -> Result<(), FindingPersistenceError> {
        let bytes =
            serde_json::to_vec(record).map_err(|_| FindingPersistenceError::MalformedRecord)?;
        if bytes.len() > MAX_JOURNAL_LINE_BYTES {
            return Err(FindingPersistenceError::OversizedJournal);
        }
        let current_size = self
            .writer
            .get_ref()
            .metadata()
            .map_err(|_| FindingPersistenceError::Io)?
            .len();
        let record_size = (bytes.len() as u64).saturating_add(1);
        if current_size.saturating_add(record_size) > MAX_JOURNAL_BYTES {
            return Err(FindingPersistenceError::OversizedJournal);
        }
        self.writer
            .write_all(&bytes)
            .map_err(|_| FindingPersistenceError::Io)?;
        self.writer
            .write_all(b"\n")
            .map_err(|_| FindingPersistenceError::Io)?;
        self.writer
            .flush()
            .map_err(|_| FindingPersistenceError::Io)?;
        self.writer
            .get_ref()
            .sync_data()
            .map_err(|_| FindingPersistenceError::Io)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{DetectionInput, SecuritySignal, detect_and_record};
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
                value_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            },
        )
        .expect("detector should create a valid finding");
        store.findings()[0].clone()
    }

    #[test]
    fn restart_replays_findings_and_status_updates() {
        let root = test_root("restart");
        let path = root.join("findings.jsonl");
        let item = finding();
        {
            let mut journal = FindingJournal::open(&path, &root, 4).expect("journal opens");
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
                    "workspace-1/namespace-1",
                    Some(ContainmentAction::Quarantine),
                )
                .expect("status update persists");
        }
        let reopened = FindingJournal::open(&path, &root, 4).expect("journal reopens");
        assert_eq!(reopened.store().findings(), std::slice::from_ref(&item));
        assert_eq!(
            reopened.store().current_status(&item.finding_id),
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
        assert!(journal.store().findings().is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
