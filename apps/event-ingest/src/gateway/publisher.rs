use crate::{GatewayError, IngestRequest};

/// What a successful `publish` actually did.
///
/// Without this, `publish` returning `Ok(())` was ambiguous: it meant either
/// "this call made the event durable" or "a previous attempt already did, and
/// I did nothing". Those need different answers to the caller, and collapsing
/// them made the gateway report an already-stored event as freshly `Accepted`.
///
/// The window is real, not theoretical. A failed fanout aborts the idempotency
/// reservation while the durable outbox row survives; the replay worker later
/// completes that row without touching the idempotency journal. The two
/// journals then disagree: the outbox knows the event is done, the idempotency
/// store has no memory of the key. A re-submission reserved cleanly, hit
/// `AlreadyComplete` in the outbox, and was answered `duplicate: false` --
/// telling a producer its event had just been accepted when in fact it had
/// been stored minutes earlier by the replay worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// This call made the event durable.
    Published,
    /// The event was already durable; this call published nothing. Only a
    /// publisher with a durable outbox can distinguish this, which is the same
    /// property `can_reconcile_commit_failure` reports.
    AlreadyComplete,
}

pub trait EventPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError>;

    /// Returns true only when a durable outbox can prove a completed publish
    /// on retry and repair a failed idempotency commit without fanout again.
    /// Plain publishers must retain an uncertain reservation instead.
    fn can_reconcile_commit_failure(&self) -> bool {
        false
    }
}
