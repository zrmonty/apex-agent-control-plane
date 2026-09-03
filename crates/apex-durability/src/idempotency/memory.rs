use std::collections::HashMap;

use super::types::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult, scope_capacity,
};
use crate::{GatewayError, GatewayErrorCode};

const MAX_IN_MEMORY_IDEMPOTENCY: usize = 1_000_000;

#[derive(Debug)]
pub struct InMemoryIdempotencyStore {
    capacity: usize,
    pub(crate) next_token: u64,
    committed: HashMap<IdempotencyKey, [u8; 32]>,
    pub(crate) pending: HashMap<IdempotencyReservation, (IdempotencyKey, [u8; 32])>,
}

impl InMemoryIdempotencyStore {
    pub fn new(capacity: usize) -> Result<Self, GatewayError> {
        if capacity == 0 || capacity > MAX_IN_MEMORY_IDEMPOTENCY {
            return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
        }
        Ok(Self {
            capacity,
            next_token: 1,
            committed: HashMap::new(),
            pending: HashMap::new(),
        })
    }
}

impl IdempotencyStore for InMemoryIdempotencyStore {
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
        let reservation = IdempotencyReservation {
            token: if self.next_token == u64::MAX {
                return Err(GatewayError::new(GatewayErrorCode::IdempotencyCapacity));
            } else {
                self.next_token
            },
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
        self.pending.remove(&reservation);
        self.committed.insert(key, hash);
        Ok(())
    }

    fn abort(&mut self, reservation: IdempotencyReservation) {
        self.pending.remove(&reservation);
    }
}
