use crate::{GatewayError, IngestRequest};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboxKey {
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    Enqueued,
    AlreadyPending,
    AlreadyComplete,
}

/// Durable outbox contract. `enqueue` must commit the canonical event before
/// the downstream fanout begins; `mark_complete` is only called after every
/// projection acknowledges the event. Pending rows are replay work.
pub trait EventOutbox: Send {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError>;
    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError>;
    fn pending(&mut self) -> Vec<IngestRequest>;
}

impl<T: EventOutbox + ?Sized> EventOutbox for Box<T> {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        (**self).enqueue(event)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        (**self).mark_complete(key)
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        (**self).pending()
    }
}
