use crate::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyReservation {
    pub(crate) token: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationResult {
    Reserved(IdempotencyReservation),
    Duplicate,
    InProgress,
    Conflict,
}

/// Derive a bounded per-scope quota from the configured store capacity.
///
/// Small test/staging stores retain their exact capacity so callers can
/// exercise exhaustion deterministically. Larger stores reserve capacity for
/// other workspaces/namespaces instead of allowing one tenant to consume the
/// entire process-wide idempotency map.
pub(super) fn scope_capacity(capacity: usize) -> usize {
    capacity.min((capacity / 16).max(2))
}

/// Transactional idempotency contract required by the production gateway.
/// Implementations must persist the key/hash atomically across replicas and
/// release reservations when the downstream publish fails. The runnable
/// gateway pairs this contract with a durable outbox: if the final idempotency
/// commit fails after publication, the live reservation is released so the
/// retry can observe the outbox's completed event and finish idempotency
/// bookkeeping without publishing a second time.
pub trait IdempotencyStore {
    fn reserve(
        &mut self,
        key: IdempotencyKey,
        payload_hash: [u8; 32],
    ) -> Result<ReservationResult, GatewayError>;
    fn commit(&mut self, reservation: IdempotencyReservation) -> Result<(), GatewayError>;
    fn abort(&mut self, reservation: IdempotencyReservation);

    /// Remove durable committed entries older than the configured retention.
    ///
    /// Backends without durable retention state may keep the default no-op;
    /// production stores override this to reclaim capacity safely.
    fn maintain(
        &mut self,
        _now_millis: u64,
        _retention_millis: u64,
    ) -> Result<(), GatewayError> {
        Ok(())
    }
}
