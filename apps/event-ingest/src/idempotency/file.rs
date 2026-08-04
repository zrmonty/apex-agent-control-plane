use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::types::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult, scope_capacity,
};
use crate::{GatewayError, GatewayErrorCode, is_lowercase_uuidv7, is_scope_identifier};

const MAX_IDEMPOTENCY_RECORD_BYTES: usize = 4096;
const MAX_IDEMPOTENCY_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum IdempotencyRecord {
    Committed {
        workspace_id: String,
        namespace_id: String,
        event_id: String,
        payload_hash: [u8; 32],
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
    file: File,
    capacity: usize,
    next_token: u64,
    committed: HashMap<IdempotencyKey, [u8; 32]>,
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
        let mut store = Self {
            file,
            capacity,
            next_token: 1,
            committed: HashMap::new(),
            pending: HashMap::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), GatewayError> {
        let reader = BufReader::new(
            self.file
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
                self.committed.insert(key, payload_hash);
            }
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
        let current_size = self
            .file
            .metadata()
            .map_err(|_| GatewayError::invalid_idempotency_configuration())?
            .len();
        if current_size.saturating_add(encoded.len() as u64) > MAX_IDEMPOTENCY_FILE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        self.file
            .write_all(&encoded)
            .and_then(|_| self.file.sync_data())
            .map_err(|_| GatewayError::new(GatewayErrorCode::Internal))
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
        self.append(&IdempotencyRecord::Committed {
            workspace_id: key.workspace_id.clone(),
            namespace_id: key.namespace_id.clone(),
            event_id: key.event_id.clone(),
            payload_hash: hash,
        })?;
        self.pending.remove(&reservation);
        self.committed.insert(key, hash);
        Ok(())
    }

    fn abort(&mut self, reservation: IdempotencyReservation) {
        self.pending.remove(&reservation);
    }
}
