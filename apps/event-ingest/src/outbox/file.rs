use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use prost::Message;
use serde::{Deserialize, Serialize};

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{GatewayError, IngestRequest, proto};

const MAX_OUTBOX_RECORD_BYTES: usize = crate::MAX_ENVELOPE_BYTES * 4;
const MAX_OUTBOX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PERSISTED_ATTEMPTS: u32 = 8;

fn payload_fingerprint(envelope: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(envelope).into()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn hex_fingerprint(fingerprint: [u8; 32]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_fingerprint(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let value = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(value, 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FileOutboxRecord {
    Pending {
        workspace_id: String,
        namespace_id: String,
        event_id: String,
        envelope: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_attempt_at_millis: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attempts: Option<u32>,
        /// When this row first entered `pending`. `None` only for journals
        /// written before this field existed; `load()` falls back to the
        /// replay-time clock for those rows rather than refusing to start,
        /// matching every other backward-compatible `Option` field on this
        /// record. Reschedule/compaction always carry the ORIGINAL value
        /// forward (see `file_ops.rs`), so this stays stable across restarts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_at_millis: Option<u64>,
    },
    Complete {
        workspace_id: String,
        namespace_id: String,
        event_id: String,
        /// Lowercase SHA-256 hex of the completed envelope. `None` only in
        /// journals written before completed rows recorded content, where a
        /// conflict cannot be proven either way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        envelope_sha256: Option<String>,
        /// Completion time for bounded idempotency retention. Legacy records
        /// without this field are retained indefinitely for safety.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completed_at_millis: Option<u64>,
        /// Retained so the control gateway can rebuild a missing inbox row
        /// even after fanout has already completed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        envelope: Option<Vec<u8>>,
    },
    Quarantined {
        workspace_id: String,
        namespace_id: String,
        event_id: String,
        envelope: Vec<u8>,
        reason: String,
        quarantined_at_millis: u64,
    },
}

/// Append-only, fsync-backed outbox for the runnable gateway.
///
/// The file is intentionally scoped beneath an operator-owned base directory.
/// Startup replays every record in order and fails closed on malformed or
/// oversized data; it never silently drops a pending event.
#[derive(Debug)]
pub struct FileOutbox {
    file: Option<File>,
    path: std::path::PathBuf,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    capacity: usize,
    pending: HashMap<OutboxKey, IngestRequest>,
    /// Completed keys map to the payload fingerprint that was completed, so a
    /// reused `event_id` carrying different content is a conflict rather than
    /// a silent "already done" acknowledgement of an event never stored.
    /// `None` marks a legacy record whose content was not journalled.
    complete: HashMap<OutboxKey, Option<[u8; 32]>>,
    complete_events: HashMap<OutboxKey, IngestRequest>,
    completed_at_millis: HashMap<OutboxKey, u64>,
    next_attempt_at_millis: HashMap<OutboxKey, u64>,
    attempts: HashMap<OutboxKey, u32>,
    quarantined: HashMap<OutboxKey, IngestRequest>,
    /// When each currently-pending row first entered `pending`. Backs
    /// `oldest_pending_millis` (Phase 0.6 item 6). See the doc comment on
    /// `FileOutboxRecord::Pending::created_at_millis` for how this survives
    /// reschedule, compaction, and restart.
    pending_since_millis: HashMap<OutboxKey, u64>,
}

impl FileOutbox {
    pub fn open(path: &Path, base: &Path, capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        let canonical_base = base
            .canonicalize()
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        let parent = path
            .parent()
            .ok_or_else(GatewayError::invalid_outbox_configuration)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        if !canonical_parent.starts_with(&canonical_base)
            || path.file_name().is_none()
            || (path.exists() && path.is_symlink())
        {
            return Err(GatewayError::invalid_outbox_configuration());
        }
        if path.exists() {
            let metadata =
                fs::metadata(path).map_err(|_| GatewayError::invalid_outbox_configuration())?;
            if !metadata.is_file() || metadata.len() > MAX_OUTBOX_FILE_BYTES {
                return Err(GatewayError::invalid_outbox_configuration());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        let lock_path = path.with_extension(format!(
            "{}.lock",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("journal")
        ));
        let writer_lock = OpenOptions::new()
            .create(true)
            // The lock file's content is never read; only its exclusive-lock
            // state is meaningful. `truncate(false)` keeps any existing
            // bytes intact instead of silently discarding them on reopen.
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        writer_lock
            .try_lock_exclusive()
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        let mut outbox = Self {
            file: Some(file),
            path: path.to_owned(),
            _writer_lock: writer_lock,
            capacity,
            pending: HashMap::new(),
            complete: HashMap::new(),
            complete_events: HashMap::new(),
            completed_at_millis: HashMap::new(),
            next_attempt_at_millis: HashMap::new(),
            attempts: HashMap::new(),
            quarantined: HashMap::new(),
            pending_since_millis: HashMap::new(),
        };
        outbox.load()?;
        Ok(outbox)
    }

    fn load(&mut self) -> Result<(), GatewayError> {
        let reader = BufReader::new(
            self.file
                .as_ref()
                .ok_or_else(GatewayError::invalid_outbox_configuration)?
                .try_clone()
                .map_err(|_| GatewayError::invalid_outbox_configuration())?,
        );
        // Tracks the byte offset immediately after the last successfully
        // parsed record, and whether at least one record has parsed so far.
        // Together these let us recognize a torn TRAILING write (see below)
        // without ever forgiving corruption anywhere else in the file.
        let mut good_bytes: u64 = 0;
        let mut parsed_any = false;
        let mut lines = reader.lines().peekable();
        while let Some(line) = lines.next() {
            let line = line.map_err(|_| GatewayError::invalid_outbox_configuration())?;
            let is_last_line = lines.peek().is_none();
            if line.is_empty() {
                // A file that ends in `\n` never yields a trailing empty
                // element from `BufRead::lines()`, but a stray blank line
                // (e.g. a doubled trailing newline) can. Treat a blank FINAL
                // line as harmless end-of-file noise rather than a torn
                // record; a blank line anywhere else is corruption and falls
                // through to the fail-closed path below exactly as today.
                if is_last_line {
                    break;
                }
                return Err(GatewayError::invalid_outbox_configuration());
            }
            if line.len() > MAX_OUTBOX_RECORD_BYTES {
                return Err(GatewayError::invalid_outbox_configuration());
            }
            let record: FileOutboxRecord = match serde_json::from_str(&line) {
                Ok(record) => record,
                Err(_) => {
                    // A record can only end up malformed on a real crash if
                    // the process/OS died mid-`write_all`/before
                    // `sync_data()` returned for the LAST record physically
                    // present in the file. Such a torn write was never
                    // acknowledged to any caller (the `enqueue`/
                    // `mark_complete` that produced it returned an error, or
                    // never returned, before the crash), so it can never
                    // represent committed state — discarding it loses
                    // nothing. Require at least one prior record to have
                    // parsed cleanly (`parsed_any`) so a file whose ONLY
                    // record is corrupt still fails closed: with no known-good
                    // prefix, "recovering" would be indistinguishable from
                    // silently accepting arbitrary corruption. Self-heal by
                    // truncating the file back to the last known-good byte
                    // offset so the journal is clean on the next append.
                    if is_last_line && parsed_any {
                        self.truncate_to(good_bytes)?;
                        break;
                    }
                    return Err(GatewayError::invalid_outbox_configuration());
                }
            };
            match record {
                FileOutboxRecord::Pending {
                    workspace_id,
                    namespace_id,
                    event_id,
                    envelope,
                    next_attempt_at_millis,
                    attempts,
                    created_at_millis,
                } => {
                    let key = OutboxKey {
                        workspace_id: workspace_id.clone(),
                        namespace_id: namespace_id.clone(),
                        event_id: event_id.clone(),
                    };
                    if envelope.is_empty() || envelope.len() > crate::MAX_ENVELOPE_BYTES {
                        return Err(GatewayError::new(
                            crate::GatewayErrorCode::InvalidOutboxConfiguration,
                        ));
                    }
                    let decoded = proto::EventEnvelope::decode(envelope.as_slice())
                        .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                    let event = IngestRequest::from_validated_transport(decoded)
                        .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                    if event.event_id.as_str() != event_id
                        || event.workspace_id.as_str() != workspace_id
                        || event.namespace_id.as_str() != namespace_id
                        || event.envelope.as_slice() != envelope.as_slice()
                    {
                        return Err(GatewayError::invalid_outbox_configuration());
                    }
                    if let Some(existing) = self.pending.get(&key) {
                        if existing.envelope != event.envelope {
                            return Err(GatewayError::idempotency_conflict());
                        }
                    } else {
                        self.quarantined.remove(&key);
                        self.pending.insert(key.clone(), event);
                    }
                    if let Some(next_attempt_at_millis) = next_attempt_at_millis {
                        self.next_attempt_at_millis
                            .insert(key.clone(), next_attempt_at_millis);
                    } else {
                        self.next_attempt_at_millis.remove(&key);
                    }
                    if let Some(attempts) = attempts {
                        self.attempts.insert(key.clone(), attempts);
                    } else {
                        self.attempts.remove(&key);
                    }
                    match created_at_millis {
                        Some(value) => {
                            self.pending_since_millis.insert(key.clone(), value);
                        }
                        // Legacy journal entry predating this field. Do not
                        // overwrite an already-known value (a later
                        // reschedule/compaction record for the same key may
                        // have already supplied one); only seed a fallback
                        // the first time this key is seen with no timestamp
                        // at all. This under-estimates age for rows that
                        // predate the upgrade, never over-estimates it.
                        None => {
                            self.pending_since_millis
                                .entry(key.clone())
                                .or_insert_with(now_millis);
                        }
                    }
                }
                FileOutboxRecord::Complete {
                    workspace_id,
                    namespace_id,
                    event_id,
                    envelope_sha256,
                    completed_at_millis,
                    envelope,
                } => {
                    let key = OutboxKey {
                        workspace_id,
                        namespace_id,
                        event_id,
                    };
                    let pending_event = self.pending.get(&key).cloned();
                    let reconstructed = match envelope {
                        Some(bytes) => {
                            let decoded = proto::EventEnvelope::decode(bytes.as_slice())
                                .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                            let event = IngestRequest::from_validated_transport(decoded)
                                .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                            if event.event_id != key.event_id
                                || event.workspace_id != key.workspace_id
                                || event.namespace_id != key.namespace_id
                                || event.envelope != bytes
                            {
                                return Err(GatewayError::invalid_outbox_configuration());
                            }
                            Some(event)
                        }
                        None => None,
                    };
                    let fingerprint = match envelope_sha256.as_deref() {
                        Some(hex) => Some(
                            parse_fingerprint(hex)
                                .ok_or_else(GatewayError::invalid_outbox_configuration)?,
                        ),
                        // Fall back to the pending record's content when the
                        // journal predates fingerprinted completions.
                        None => self
                            .pending
                            .get(&key)
                            .map(|event| payload_fingerprint(&event.envelope)),
                    };
                    self.pending.remove(&key);
                    self.pending_since_millis.remove(&key);
                    self.complete.insert(key.clone(), fingerprint);
                    if let Some(event) = reconstructed.or(pending_event) {
                        self.complete_events.insert(key.clone(), event);
                    }
                    if let Some(completed_at_millis) = completed_at_millis {
                        self.completed_at_millis.insert(key, completed_at_millis);
                    }
                }
                FileOutboxRecord::Quarantined {
                    workspace_id,
                    namespace_id,
                    event_id,
                    envelope,
                    reason: _,
                    quarantined_at_millis: _,
                } => {
                    let key = OutboxKey {
                        workspace_id: workspace_id.clone(),
                        namespace_id: namespace_id.clone(),
                        event_id: event_id.clone(),
                    };
                    let decoded = proto::EventEnvelope::decode(envelope.as_slice())
                        .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                    let event = IngestRequest::from_validated_transport(decoded)
                        .map_err(|_| GatewayError::invalid_outbox_configuration())?;
                    if event.event_id != event_id
                        || event.workspace_id != workspace_id
                        || event.namespace_id != namespace_id
                    {
                        return Err(GatewayError::invalid_outbox_configuration());
                    }
                    self.pending.remove(&key);
                    self.pending_since_millis.remove(&key);
                    self.quarantined.insert(key, event);
                }
            }
            good_bytes = good_bytes
                .saturating_add(line.len() as u64)
                .saturating_add(1);
            parsed_any = true;
            if self.pending.len() + self.complete.len() + self.quarantined.len() > self.capacity {
                return Err(GatewayError::new(
                    crate::GatewayErrorCode::IdempotencyCapacity,
                ));
            }
        }
        Ok(())
    }

    /// Truncates the journal file to `len` bytes. Used only to drop a
    /// confirmed torn trailing record so the file is clean (self-healing)
    /// for the next append.
    ///
    /// This intentionally opens a fresh, non-append handle rather than
    /// reusing `self.file`: on Windows, an append-mode handle is granted
    /// `FILE_APPEND_DATA` but never `FILE_WRITE_DATA` (even when `.write`
    /// is also requested), and `set_len`/`SetEndOfFile` requires the latter.
    fn truncate_to(&self, len: u64) -> Result<(), GatewayError> {
        let truncator = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|_| GatewayError::invalid_outbox_configuration())?;
        truncator
            .set_len(len)
            .map_err(|_| GatewayError::invalid_outbox_configuration())
    }

    fn append(&mut self, record: &FileOutboxRecord) -> Result<(), GatewayError> {
        self.append_batch(std::slice::from_ref(record))
    }

    fn append_batch(&mut self, records: &[FileOutboxRecord]) -> Result<(), GatewayError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut encoded = Vec::new();
        for record in records {
            let mut record_bytes = serde_json::to_vec(record)
                .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
            record_bytes.push(b'\n');
            if record_bytes.len() > MAX_OUTBOX_RECORD_BYTES {
                return Err(GatewayError::new(crate::GatewayErrorCode::PayloadTooLarge));
            }
            encoded.extend_from_slice(&record_bytes);
        }
        let current_size = self
            .file
            .as_ref()
            .ok_or_else(GatewayError::invalid_outbox_configuration)?
            .metadata()
            .map_err(|_| GatewayError::invalid_outbox_configuration())?
            .len();
        if current_size.saturating_add(encoded.len() as u64) > MAX_OUTBOX_FILE_BYTES {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        self.file
            .as_mut()
            .ok_or_else(GatewayError::invalid_outbox_configuration)?
            .write_all(&encoded)
            .and_then(|_| {
                self.file
                    .as_ref()
                    .ok_or(std::io::Error::other("outbox journal is closed"))?
                    .sync_data()
            })
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))
    }
}


#[path = "file_ops.rs"]
mod file_ops;
