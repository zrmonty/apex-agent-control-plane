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
        // Set when the final line in the file is a torn trailing write (see
        // below), so the file can be truncated back to the last known-good
        // record once the writer handle is open below.
        let mut torn_trailing_len: Option<u64> = None;
        if resolved.exists() {
            let reader =
                BufReader::new(File::open(&resolved).map_err(|_| FindingPersistenceError::Io)?);
            let mut replayed_bytes = 0_u64;
            let mut good_bytes = 0_u64;
            let mut parsed_any = false;
            let mut lines = reader.lines().peekable();
            while let Some(line) = lines.next() {
                let line = line.map_err(|_| FindingPersistenceError::Io)?;
                let is_last_line = lines.peek().is_none();
                if line.is_empty() {
                    // A file ending in `\n` never yields a trailing empty
                    // element from `BufRead::lines()`, but a stray blank
                    // line (e.g. a doubled trailing newline) can. Treat a
                    // blank FINAL line as harmless end-of-file noise, not a
                    // torn record; a blank line anywhere else is corruption
                    // and fails closed exactly as today.
                    if is_last_line {
                        break;
                    }
                    return Err(FindingPersistenceError::MalformedRecord);
                }
                let candidate_bytes = replayed_bytes
                    .saturating_add(line.len() as u64)
                    .saturating_add(1);
                if candidate_bytes > MAX_JOURNAL_BYTES {
                    return Err(FindingPersistenceError::OversizedJournal);
                }
                if line.len() > MAX_JOURNAL_LINE_BYTES {
                    return Err(FindingPersistenceError::OversizedJournal);
                }
                let record: JournalRecord = match serde_json::from_str(&line) {
                    Ok(record) => record,
                    Err(_) => {
                        // A record can only end up malformed on a real crash
                        // if the process/OS died mid-write/before
                        // `sync_data()` returned for the LAST record
                        // physically present in the file. Such a torn write
                        // was never acknowledged to any caller (the
                        // `append`/`transition` that produced it returned an
                        // error, or never returned, before the crash), so it
                        // can never represent committed state — discarding
                        // it loses nothing. Require at least one prior
                        // record to have parsed cleanly (`parsed_any`) so a
                        // file whose ONLY record is corrupt still fails
                        // closed: with no known-good prefix, "recovering"
                        // would be indistinguishable from silently accepting
                        // arbitrary corruption.
                        if is_last_line && parsed_any {
                            torn_trailing_len = Some(good_bytes);
                            break;
                        }
                        return Err(FindingPersistenceError::MalformedRecord);
                    }
                };
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
                replayed_bytes = candidate_bytes;
                good_bytes = replayed_bytes;
                parsed_any = true;
            }
        }
        if let Some(len) = torn_trailing_len {
            // Self-heal: drop the torn trailing record so the file is clean
            // for the next append. This uses a fresh, non-append handle:
            // on Windows an append-mode handle is granted `FILE_APPEND_DATA`
            // but never `FILE_WRITE_DATA` (even when `.write` is also
            // requested), and `set_len`/`SetEndOfFile` requires the latter.
            let truncator = OpenOptions::new()
                .write(true)
                .open(&resolved)
                .map_err(|_| FindingPersistenceError::Io)?;
            truncator
                .set_len(len)
                .map_err(|_| FindingPersistenceError::Io)?;
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
