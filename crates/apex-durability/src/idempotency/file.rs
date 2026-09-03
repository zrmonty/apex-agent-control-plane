use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::types::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult, scope_capacity,
};
use crate::{GatewayError, GatewayErrorCode, is_lowercase_uuidv7, is_scope_identifier};

const MAX_IDEMPOTENCY_RECORD_BYTES: usize = 4096;
const MAX_IDEMPOTENCY_FILE_BYTES: u64 = 256 * 1024 * 1024;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum IdempotencyRecord {
    Committed {
        workspace_id: String,
        namespace_id: String,
        event_id: String,
        payload_hash: [u8; 32],
        /// Legacy records omit this field and are retained indefinitely.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        committed_at_millis: Option<u64>,
    },
}

/// Restart-safe committed idempotency journal for the single gateway.
///
/// Reservations stay in memory only while a request is running. The durable
/// outbox is the recovery authority for a crash between fanout and commit;
/// committed keys are persisted before the reservation is released. This
/// avoids accepting a changed payload after restart while allowing a pending
/// request to be reconciled by the outbox replay worker.
#[derive(Debug)]
pub struct FileIdempotencyStore {
    file: Option<File>,
    path: PathBuf,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    capacity: usize,
    next_token: u64,
    committed: HashMap<IdempotencyKey, [u8; 32]>,
    committed_at_millis: HashMap<IdempotencyKey, Option<u64>>,
    pending: HashMap<IdempotencyReservation, (IdempotencyKey, [u8; 32])>,
}

impl FileIdempotencyStore {
    pub fn open(path: &Path, base: &Path, capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        let canonical_base = base
            .canonicalize()
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        let parent = path
            .parent()
            .ok_or_else(GatewayError::invalid_idempotency_configuration)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        if !canonical_parent.starts_with(&canonical_base)
            || path.file_name().is_none()
            || (path.exists() && path.is_symlink())
        {
            return Err(GatewayError::invalid_idempotency_configuration());
        }
        if path.exists() {
            let metadata = fs::metadata(path)
                .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
            if !metadata.is_file() || metadata.len() > MAX_IDEMPOTENCY_FILE_BYTES {
                return Err(GatewayError::invalid_idempotency_configuration());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
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
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        writer_lock
            .try_lock_exclusive()
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
        let mut store = Self {
            file: Some(file),
            path: path.to_owned(),
            _writer_lock: writer_lock,
            capacity,
            next_token: 1,
            committed: HashMap::new(),
            committed_at_millis: HashMap::new(),
            pending: HashMap::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), GatewayError> {
        let reader = BufReader::new(
            self.file
                .as_ref()
                .ok_or_else(GatewayError::invalid_idempotency_configuration)?
                .try_clone()
                .map_err(|_| GatewayError::invalid_idempotency_configuration())?,
        );
        for line in reader.lines() {
            let line = line.map_err(|_| GatewayError::invalid_idempotency_configuration())?;
            if line.len() > MAX_IDEMPOTENCY_RECORD_BYTES {
                return Err(GatewayError::invalid_idempotency_configuration());
            }
            let record: IdempotencyRecord = serde_json::from_str(&line)
                .map_err(|_| GatewayError::invalid_idempotency_configuration())?;
            let IdempotencyRecord::Committed {
                workspace_id,
                namespace_id,
                event_id,
                payload_hash,
                committed_at_millis,
            } = record;
            if !is_scope_identifier(&workspace_id)
                || !is_scope_identifier(&namespace_id)
                || !is_lowercase_uuidv7(&event_id)
            {
                return Err(GatewayError::invalid_idempotency_configuration());
            }
            let key = IdempotencyKey {
                workspace_id,
                namespace_id,
                event_id,
            };
            if let Some(existing) = self.committed.get(&key) {
                if existing != &payload_hash {
                    return Err(GatewayError::idempotency_conflict());
                }
            } else {
                self.committed.insert(key.clone(), payload_hash);
            }
            self.committed_at_millis.insert(key, committed_at_millis);
            if self.committed.len() > self.capacity {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
            }
        }
        Ok(())
    }

    fn append(&mut self, record: &IdempotencyRecord) -> Result<(), GatewayError> {
        let mut encoded = serde_json::to_vec(record)
            .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?;
        encoded.push(b'\n');
        if encoded.len() > MAX_IDEMPOTENCY_RECORD_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(GatewayError::invalid_idempotency_configuration)?;
        let current_size = file
            .metadata()
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?
            .len();
        if current_size.saturating_add(encoded.len() as u64) > MAX_IDEMPOTENCY_FILE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        file.write_all(&encoded)
            .and_then(|_| file.sync_data())
            .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))
    }

    fn compact_journal(&mut self) -> Result<(), GatewayError> {
        let mut encoded = Vec::new();
        for (key, payload_hash) in &self.committed {
            let record = IdempotencyRecord::Committed {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                payload_hash: *payload_hash,
                committed_at_millis: self.committed_at_millis.get(key).copied().flatten(),
            };
            let mut record_bytes = serde_json::to_vec(&record)
                .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?;
            record_bytes.push(b'\n');
            if record_bytes.len() > MAX_IDEMPOTENCY_RECORD_BYTES
                || encoded.len().saturating_add(record_bytes.len())
                    > MAX_IDEMPOTENCY_FILE_BYTES as usize
            {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
            }
            encoded.extend_from_slice(&record_bytes);
        }

        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(GatewayError::invalid_idempotency_configuration)?;
        let temp_path = self.path.with_file_name(format!(
            ".{name}.compact-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))?;
        let result = temp
            .write_all(&encoded)
            .and_then(|_| temp.sync_data())
            .map_err(|_| GatewayError::new(GatewayErrorCode::Internal));
        if result.is_err() {
            drop(temp);
            let _ = fs::remove_file(&temp_path);
            return result;
        }
        drop(temp);
        drop(
            self.file
                .take()
                .ok_or_else(GatewayError::invalid_idempotency_configuration)?,
        );
        if fs::rename(&temp_path, &self.path).is_err() {
            let _ = fs::remove_file(&temp_path);
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&self.path)
                    .map_err(|_| GatewayError::invalid_idempotency_configuration())?,
            );
            return Err(GatewayError::new(GatewayErrorCode::Internal));
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| GatewayError::invalid_idempotency_configuration())?,
        );
        Ok(())
    }
}

impl IdempotencyStore for FileIdempotencyStore {
    fn reserve(
        &mut self,
        key: IdempotencyKey,
        payload_hash: [u8; 32],
    ) -> Result<ReservationResult, GatewayError> {
        if let Some(existing) = self.committed.get(&key) {
            return Ok(if existing == &payload_hash {
                ReservationResult::Duplicate
            } else {
                ReservationResult::Conflict
            });
        }
        if let Some((_, existing)) = self
            .pending
            .values()
            .find(|(pending_key, _)| pending_key == &key)
        {
            return Ok(if existing == &payload_hash {
                ReservationResult::InProgress
            } else {
                ReservationResult::Conflict
            });
        }
        let scope_entries = self
            .committed
            .keys()
            .filter(|existing| {
                existing.workspace_id == key.workspace_id
                    && existing.namespace_id == key.namespace_id
            })
            .count()
            + self
                .pending
                .values()
                .filter(|(existing, _)| {
                    existing.workspace_id == key.workspace_id
                        && existing.namespace_id == key.namespace_id
                })
                .count();
        if scope_entries >= scope_capacity(self.capacity)
            || self.committed.len() + self.pending.len() >= self.capacity
        {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        if self.next_token == u64::MAX {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        let reservation = IdempotencyReservation {
            token: self.next_token,
        };
        self.next_token += 1;
        self.pending.insert(reservation, (key, payload_hash));
        Ok(ReservationResult::Reserved(reservation))
    }

    fn commit(&mut self, reservation: IdempotencyReservation) -> Result<(), GatewayError> {
        let (key, hash) = self
            .pending
            .get(&reservation)
            .cloned()
            .ok_or_else(GatewayError::internal)?;
        let committed_at_millis = now_millis();
        self.append(&IdempotencyRecord::Committed {
            workspace_id: key.workspace_id.clone(),
            namespace_id: key.namespace_id.clone(),
            event_id: key.event_id.clone(),
            payload_hash: hash,
            committed_at_millis: Some(committed_at_millis),
        })?;
        self.pending.remove(&reservation);
        self.committed.insert(key.clone(), hash);
        self.committed_at_millis
            .insert(key, Some(committed_at_millis));
        Ok(())
    }

    fn abort(&mut self, reservation: IdempotencyReservation) {
        self.pending.remove(&reservation);
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        let cutoff = now_millis.saturating_sub(retention_millis);
        let expired_keys: Vec<IdempotencyKey> = self
            .committed_at_millis
            .iter()
            .filter_map(|(key, committed_at)| {
                committed_at
                    .filter(|committed_at| *committed_at <= cutoff)
                    .map(|_| key.clone())
            })
            .collect();
        if expired_keys.is_empty() {
            return Ok(());
        }

        let removed: Vec<(IdempotencyKey, [u8; 32], Option<u64>)> = expired_keys
            .into_iter()
            .filter_map(|key| {
                let payload_hash = self.committed.remove(&key)?;
                let committed_at = self.committed_at_millis.remove(&key)?;
                Some((key, payload_hash, committed_at))
            })
            .collect();
        if let Err(error) = self.compact_journal() {
            for (key, payload_hash, committed_at) in removed {
                self.committed.insert(key.clone(), payload_hash);
                self.committed_at_millis.insert(key, committed_at);
            }
            return Err(error);
        }
        Ok(())
    }
}
