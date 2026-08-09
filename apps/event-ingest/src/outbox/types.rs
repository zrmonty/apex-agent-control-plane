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

    /// Settles a group of successfully published events. Implementations may
    /// use one durable write/transaction; the default preserves the original
    /// per-key behavior for small or embedded backends.
    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        for key in keys {
            self.mark_complete(key)?;
        }
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest>;
}

impl<T: EventOutbox + ?Sized> EventOutbox for Box<T> {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        (**self).enqueue(event)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        (**self).mark_complete(key)
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        (**self).mark_complete_many(keys)
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        (**self).pending()
    }
}
