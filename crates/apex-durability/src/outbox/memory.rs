use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
    complete_events: HashMap<OutboxKey, IngestRequest>,
    completed_at_millis: HashMap<OutboxKey, u64>,
    next_attempt_at_millis: HashMap<OutboxKey, u64>,
    quarantined: HashMap<OutboxKey, IngestRequest>,
    /// When each currently-pending row entered the pending state. Backs
    /// `oldest_pending_millis` (Phase 0.6 item 6). Cleared whenever a row
    /// leaves `pending` (completed or quarantined) and re-seeded to "now" on
    /// `requeue_quarantined`, matching that call's existing choice to reset
    /// `attempts`/`next_attempt_at_millis` -- a requeue starts a fresh replay
    /// window, not a continuation of the original one.
    pending_since_millis: HashMap<OutboxKey, u64>,
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
            complete_events: HashMap::new(),
            completed_at_millis: HashMap::new(),
            next_attempt_at_millis: HashMap::new(),
            quarantined: HashMap::new(),
            pending_since_millis: HashMap::new(),
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
        if self.quarantined.contains_key(&key) {
            return Ok(EnqueueResult::AlreadyPending);
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
        self.pending_since_millis.insert(key.clone(), now_millis());
        self.pending.insert(key, event.clone());
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        match self.pending.remove(key) {
            Some(event) => {
                let completed_at = now_millis();
                self.complete
                    .insert(key.clone(), payload_fingerprint(&event.envelope));
                self.complete_events.insert(key.clone(), event);
                self.completed_at_millis.insert(key.clone(), completed_at);
                self.next_attempt_at_millis.remove(key);
                self.pending_since_millis.remove(key);
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

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        let now = now_millis();
        Ok(self
            .pending
            .iter()
            .filter(|(key, _)| self.next_attempt_at_millis.get(*key).copied().unwrap_or(0) <= now)
            .take(limit)
            .map(|(_, event)| event.clone())
            .collect())
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        Ok(self.pending.len() as u64)
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(self
            .completed_at_millis
            .iter()
            .filter(|(_, completed_at)| **completed_at >= since_millis)
            .filter_map(|(key, _)| self.complete_events.get(key).cloned())
            .take(limit)
            .collect())
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(self.pending.values().take(limit).cloned().collect())
    }

    fn reschedule(
        &mut self,
        keys: &[OutboxKey],
        after: std::time::Duration,
    ) -> Result<(), GatewayError> {
        // The replay worker owns the in-process monotonic deadline. This
        // backend is test/embedded durability and has no restart contract for
        // retry timing; keeping scheduling here would bind paused-clock tests
        // to wall-clock milliseconds.
        let _ = (keys, after);
        Ok(())
    }

    fn quarantine(
        &mut self,
        keys: &[OutboxKey],
        _reason: &'static str,
    ) -> Result<(), GatewayError> {
        for key in keys {
            self.next_attempt_at_millis.remove(key);
            self.pending_since_millis.remove(key);
            if let Some(event) = self.pending.remove(key) {
                self.quarantined.insert(key.clone(), event);
            }
        }
        Ok(())
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        Ok(self.quarantined.keys().take(limit).cloned().collect())
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        Ok(self.quarantined.len() as u64)
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        for key in keys {
            if let Some(event) = self.quarantined.remove(key) {
                self.pending_since_millis.insert(key.clone(), now_millis());
                self.pending.insert(key.clone(), event);
            }
        }
        Ok(())
    }

    fn oldest_pending_millis(&mut self) -> Result<Option<u64>, GatewayError> {
        let now = now_millis();
        Ok(self
            .pending_since_millis
            .values()
            .min()
            .map(|oldest| now.saturating_sub(*oldest)))
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
