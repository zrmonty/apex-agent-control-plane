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

fn payload_fingerprint(envelope: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(envelope).into()
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
    completed_at_millis: HashMap<OutboxKey, u64>,
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
            completed_at_millis: HashMap::new(),
        };
        outbox.load()?;
        Ok(outbox)
    }

    fn load(&mut self) -> Result<(), GatewayError> {
        let reader = BufReader::new(
            self.file
                .as_ref()
                .ok_or_else(|| GatewayError::invalid_outbox_configuration())?
                .try_clone()
                .map_err(|_| GatewayError::invalid_outbox_configuration())?,
        );
        for line in reader.lines() {
            let line = line.map_err(|_| GatewayError::invalid_outbox_configuration())?;
            if line.len() > MAX_OUTBOX_RECORD_BYTES {
                return Err(GatewayError::invalid_outbox_configuration());
            }
            let record: FileOutboxRecord = serde_json::from_str(&line)
                .map_err(|_| GatewayError::invalid_outbox_configuration())?;
            match record {
                FileOutboxRecord::Pending {
                    workspace_id,
                    namespace_id,
                    event_id,
                    envelope,
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
                        self.pending.insert(key, event);
                    }
                }
                FileOutboxRecord::Complete {
                    workspace_id,
                    namespace_id,
                    event_id,
                    envelope_sha256,
                    completed_at_millis,
                } => {
                    let key = OutboxKey {
                        workspace_id,
                        namespace_id,
                        event_id,
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
                    self.complete.insert(key.clone(), fingerprint);
                    if let Some(completed_at_millis) = completed_at_millis {
                        self.completed_at_millis.insert(key, completed_at_millis);
                    }
                }
            }
            if self.pending.len() + self.complete.len() > self.capacity {
                return Err(GatewayError::new(
                    crate::GatewayErrorCode::IdempotencyCapacity,
                ));
            }
        }
        Ok(())
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

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

impl FileOutbox {
    fn compact_journal(&mut self) -> Result<(), GatewayError> {
        let mut records = Vec::with_capacity(self.pending.len() + self.complete.len());
        for (key, event) in &self.pending {
            records.push(FileOutboxRecord::Pending {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope.clone(),
            });
        }
        for (key, fingerprint) in &self.complete {
            records.push(FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: fingerprint.map(hex_fingerprint),
                completed_at_millis: self.completed_at_millis.get(key).copied(),
            });
        }
        let mut encoded = Vec::new();
        for record in records {
            let mut bytes = serde_json::to_vec(&record)
                .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
            bytes.push(b'\n');
            encoded.extend_from_slice(&bytes);
        }
        if encoded.len() as u64 > MAX_OUTBOX_FILE_BYTES {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(GatewayError::invalid_outbox_configuration)?;
        let temp_path = self.path.with_file_name(format!(
            ".{name}.compact-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
        let result = temp
            .write_all(&encoded)
            .and_then(|_| temp.sync_data())
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal));
        if result.is_err() {
            drop(temp);
            let _ = fs::remove_file(&temp_path);
            return result;
        }
        drop(temp);
        drop(self.file.take().ok_or_else(GatewayError::invalid_outbox_configuration)?);
        if fs::rename(&temp_path, &self.path).is_err() {
            let _ = fs::remove_file(&temp_path);
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&self.path)
                    .map_err(|_| GatewayError::invalid_outbox_configuration())?,
            );
            return Err(GatewayError::new(crate::GatewayErrorCode::Internal));
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| GatewayError::invalid_outbox_configuration())?,
        );
        Ok(())
    }
}

impl EventOutbox for FileOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        if let Some(fingerprint) = self.complete.get(&key) {
            return match fingerprint {
                Some(stored) if *stored == payload_fingerprint(&event.envelope) => {
                    Ok(EnqueueResult::AlreadyComplete)
                }
                Some(_) => Err(GatewayError::idempotency_conflict()),
                // Legacy record with no journalled content: a conflict cannot
                // be proven, so preserve the historical accept-as-done result.
                None => Ok(EnqueueResult::AlreadyComplete),
            };
        }
        if let Some(existing) = self.pending.get(&key) {
            if existing.envelope == event.envelope {
                return Ok(EnqueueResult::AlreadyPending);
            }
            return Err(GatewayError::idempotency_conflict());
        }
        if self.pending.len() + self.complete.len() >= self.capacity {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        self.append(&FileOutboxRecord::Pending {
            workspace_id: key.workspace_id.clone(),
            namespace_id: key.namespace_id.clone(),
            event_id: key.event_id.clone(),
            envelope: event.envelope.clone(),
        })?;
        self.pending.insert(key, event.clone());
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        if !self.pending.contains_key(key) && !self.complete.contains_key(key) {
            return Err(GatewayError::internal());
        }
        if !self.complete.contains_key(key) {
            let fingerprint = self
                .pending
                .get(key)
                .map(|event| payload_fingerprint(&event.envelope));
            self.append(&FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: fingerprint.map(hex_fingerprint),
                completed_at_millis: Some(now_millis()),
            })?;
            self.pending.remove(key);
            self.complete.insert(key.clone(), fingerprint);
            self.completed_at_millis.insert(key.clone(), now_millis());
        }
        Ok(())
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        let mut records = Vec::new();
        for key in keys {
            if self.complete.contains_key(key) {
                continue;
            }
            let Some(event) = self.pending.get(key) else {
                return Err(GatewayError::internal());
            };
            records.push(FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: Some(hex_fingerprint(payload_fingerprint(&event.envelope))),
                completed_at_millis: Some(now_millis()),
            });
        }
        self.append_batch(&records)?;
        for key in keys {
            if self.complete.contains_key(key) {
                continue;
            }
            let Some(event) = self.pending.remove(key) else {
                return Err(GatewayError::internal());
            };
            let fingerprint = payload_fingerprint(&event.envelope);
            self.complete.insert(key.clone(), Some(fingerprint));
            self.completed_at_millis.insert(key.clone(), now_millis());
        }
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }

    fn pending_batch(&mut self, limit: usize) -> Vec<IngestRequest> {
        self.pending.values().take(limit).cloned().collect()
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        let cutoff = now_millis.saturating_sub(retention_millis);
        let previous_complete = self.complete.clone();
        let previous_completed_at = self.completed_at_millis.clone();
        let expired: Vec<_> = self
            .completed_at_millis
            .iter()
            .filter_map(|(key, completed_at)| (*completed_at <= cutoff).then_some(key.clone()))
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        for key in &expired {
            self.complete.remove(key);
            self.completed_at_millis.remove(key);
        }
        if let Err(error) = self.compact_journal() {
            self.complete = previous_complete;
            self.completed_at_millis = previous_completed_at;
            return Err(error);
        }
        Ok(())
    }
}
