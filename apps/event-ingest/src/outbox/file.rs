use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use fs2::FileExt;
use prost::Message;
use serde::{Deserialize, Serialize};

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{GatewayError, IngestRequest, proto};

const MAX_OUTBOX_RECORD_BYTES: usize = crate::MAX_ENVELOPE_BYTES * 4;
const MAX_OUTBOX_FILE_BYTES: u64 = 256 * 1024 * 1024;

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
    },
}

/// Append-only, fsync-backed outbox for the runnable gateway.
///
/// The file is intentionally scoped beneath an operator-owned base directory.
/// Startup replays every record in order and fails closed on malformed or
/// oversized data; it never silently drops a pending event.
#[derive(Debug)]
pub struct FileOutbox {
    file: File,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    capacity: usize,
    pending: HashMap<OutboxKey, IngestRequest>,
    complete: HashSet<OutboxKey>,
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
            file,
            _writer_lock: writer_lock,
            capacity,
            pending: HashMap::new(),
            complete: HashSet::new(),
        };
        outbox.load()?;
        Ok(outbox)
    }

    fn load(&mut self) -> Result<(), GatewayError> {
        let reader = BufReader::new(
            self.file
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
                } => {
                    let key = OutboxKey {
                        workspace_id,
                        namespace_id,
                        event_id,
                    };
                    self.pending.remove(&key);
                    self.complete.insert(key);
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
        let mut encoded = serde_json::to_vec(record)
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
        encoded.push(b'\n');
        if encoded.len() > MAX_OUTBOX_RECORD_BYTES {
            return Err(GatewayError::new(crate::GatewayErrorCode::PayloadTooLarge));
        }
        let current_size = self
            .file
            .metadata()
            .map_err(|_| GatewayError::invalid_outbox_configuration())?
            .len();
        if current_size.saturating_add(encoded.len() as u64) > MAX_OUTBOX_FILE_BYTES {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        self.file
            .write_all(&encoded)
            .and_then(|_| self.file.sync_data())
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))
    }
}

impl EventOutbox for FileOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        if self.complete.contains(&key) {
            return Ok(EnqueueResult::AlreadyComplete);
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
        if !self.pending.contains_key(key) && !self.complete.contains(key) {
            return Err(GatewayError::internal());
        }
        if !self.complete.contains(key) {
            self.append(&FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
            })?;
            self.pending.remove(key);
            self.complete.insert(key.clone());
        }
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }
}
