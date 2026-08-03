use std::collections::HashMap;

use crate::{GatewayError, GatewayErrorCode};

const MAX_IN_MEMORY_IDEMPOTENCY: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyReservation {
    token: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationResult {
    Reserved(IdempotencyReservation),
    Duplicate,
    InProgress,
    Conflict,
}

/// Transactional idempotency contract required by the production gateway.
/// Implementations must persist the key/hash atomically across replicas and
/// release reservations when the downstream publish fails. Once publish has
/// succeeded, a commit failure must leave the reservation in an in-progress or
/// uncertain state until a recovery worker reconciles it.
pub trait IdempotencyStore {
    fn reserve(
        &mut self,
        key: IdempotencyKey,
        payload_hash: [u8; 32],
    ) -> Result<ReservationResult, GatewayError>;
    fn commit(&mut self, reservation: IdempotencyReservation) -> Result<(), GatewayError>;
    fn abort(&mut self, reservation: IdempotencyReservation);
}

#[derive(Debug)]
pub struct InMemoryIdempotencyStore {
    capacity: usize,
    next_token: u64,
    committed: HashMap<IdempotencyKey, [u8; 32]>,
    pending: HashMap<IdempotencyReservation, (IdempotencyKey, [u8; 32])>,
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
        if self.committed.len() + self.pending.len() >= self.capacity {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(event_id: &str) -> IdempotencyKey {
        IdempotencyKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event_id.into(),
        }
    }

    #[test]
    fn reservation_commit_duplicate_conflict_and_abort_are_distinct() {
        let mut store = InMemoryIdempotencyStore::new(2).unwrap();
        let hash = [7; 32];
        let reservation = match store.reserve(key("one"), hash).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        assert_eq!(
            store.reserve(key("one"), hash).unwrap(),
            ReservationResult::InProgress
        );
        assert_eq!(
            store.reserve(key("one"), [8; 32]).unwrap(),
            ReservationResult::Conflict
        );
        store.commit(reservation).unwrap();
        let pending = match store.reserve(key("two"), [9; 32]).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        store.abort(pending);
        assert!(matches!(
            store.reserve(key("two"), [9; 32]).unwrap(),
            ReservationResult::Reserved(_)
        ));
    }

    #[test]
    fn failed_commit_does_not_release_an_uncertain_reservation() {
        let mut store = InMemoryIdempotencyStore::new(2).unwrap();
        let reservation = match store.reserve(key("uncertain"), [4; 32]).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        assert!(store.commit(IdempotencyReservation { token: 999 }).is_err());
        assert_eq!(
            store.reserve(key("uncertain"), [4; 32]).unwrap(),
            ReservationResult::InProgress
        );
        store.commit(reservation).unwrap();
        assert_eq!(
            store.reserve(key("uncertain"), [4; 32]).unwrap(),
            ReservationResult::Duplicate
        );
    }

    #[test]
    fn token_exhaustion_fails_closed_before_u64_wraparound() {
        let mut store = InMemoryIdempotencyStore::new(1).unwrap();
        store.next_token = u64::MAX;

        let error = store.reserve(key("exhausted"), [1; 32]).unwrap_err();

        assert_eq!(error.code, GatewayErrorCode::IdempotencyCapacity);
        assert!(store.pending.is_empty());
        assert_eq!(store.next_token, u64::MAX);
    }
}
