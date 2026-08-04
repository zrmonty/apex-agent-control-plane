use crate::{GatewayError, IngestRequest};

pub trait EventPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError>;

    /// Returns true only when a durable outbox can prove a completed publish
    /// on retry and repair a failed idempotency commit without fanout again.
    /// Plain publishers must retain an uncertain reservation instead.
    fn can_reconcile_commit_failure(&self) -> bool {
        false
    }
}
