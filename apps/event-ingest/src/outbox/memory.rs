use std::collections::HashMap;

use sha2::{Digest, Sha256};

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{GatewayError, IngestRequest};

/// Completed keys retain the payload fingerprint, not just the key. Matching a
/// completed key alone would let a reused `event_id` carrying different content
/// be answered `AlreadyComplete` -- acknowledging an event that is never stored
/// and discarding the idempotency-conflict signal.
pub(crate) fn payload_fingerprint(envelope: &[u8]) -> [u8; 32] {
    Sha256::digest(envelope).into()
}

#[derive(Debug)]
pub struct InMemoryOutbox {
    capacity: usize,
    pending: HashMap<OutboxKey, IngestRequest>,
    complete: HashMap<OutboxKey, [u8; 32]>,
}

impl InMemoryOutbox {
    pub fn new(capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        Ok(Self {
            capacity,
            pending: HashMap::new(),
            complete: HashMap::new(),
        })
    }
}

impl EventOutbox for InMemoryOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        if let Some(fingerprint) = self.complete.get(&key) {
            if *fingerprint == payload_fingerprint(&event.envelope) {
                return Ok(EnqueueResult::AlreadyComplete);
            }
            return Err(GatewayError::idempotency_conflict());
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
        self.pending.insert(key, event.clone());
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        match self.pending.remove(key) {
            Some(event) => {
                self.complete
                    .insert(key.clone(), payload_fingerprint(&event.envelope));
                Ok(())
            }
            // Already complete is idempotent; unknown keys are a caller bug.
            None if self.complete.contains_key(key) => Ok(()),
            None => Err(GatewayError::internal()),
        }
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }
}
