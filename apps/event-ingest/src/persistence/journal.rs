use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::FindingPersistenceError;
use crate::Caller;
use crate::security::{
    ContainmentAction, DetectionInput, FindingStatus, FindingStatusUpdate, FindingStore,
    SecurityFinding, detection_finding,
};

pub(crate) const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
enum JournalRecord {
    Finding(SecurityFinding),
    Status(FindingStatusUpdate),
}

/// Single-writer, append-only local journal. Callers must serialize access to
/// one path at the process/deployment level; this seam is not a multi-writer
/// database and intentionally has no distributed locking protocol.
pub struct FindingJournal {
    path: PathBuf,
    writer: BufWriter<File>,
    store: FindingStore,
}

// The journal owns a complete multi-tenant store. Keep debug output limited to
// operational metadata so accidental diagnostics cannot dump findings.
impl fmt::Debug for FindingJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FindingJournal")
            .field("path", &self.path)
            .field("store", &self.store)
            .finish()
    }
}

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
                            .transition_replayed(
                                &update.finding_id,
                                update.from,
                                update.to,
                                &update.actor_scope,
                                &update.actor_subject,
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

    pub fn record_detection(
        &mut self,
        input: DetectionInput,
    ) -> Result<bool, FindingPersistenceError> {
        self.append(detection_finding(input).map_err(FindingPersistenceError::Store)?)
    }

    pub(crate) fn append(
        &mut self,
        finding: SecurityFinding,
    ) -> Result<bool, FindingPersistenceError> {
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
        caller: &Caller,
        actor_scope: &str,
        action: Option<ContainmentAction>,
    ) -> Result<(), FindingPersistenceError> {
        let before = self.store.clone();
        self.store
            .transition(finding_id, expected, to, caller, actor_scope, action)
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
