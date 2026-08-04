use std::collections::{HashMap, HashSet};

use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{GatewayError, IngestRequest};

#[derive(Debug)]
pub struct InMemoryOutbox {
    capacity: usize,
    pending: HashMap<OutboxKey, IngestRequest>,
    complete: HashSet<OutboxKey>,
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
            complete: HashSet::new(),
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
        self.pending.insert(key, event.clone());
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        if self.pending.remove(key).is_none() && !self.complete.contains(key) {
            return Err(GatewayError::internal());
        }
        self.complete.insert(key.clone());
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }
}
