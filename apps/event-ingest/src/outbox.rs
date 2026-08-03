use std::collections::{HashMap, HashSet};

use crate::{EventPublisher, GatewayError, IngestRequest};

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
pub trait EventOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError>;
    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError>;
    fn pending(&self) -> Vec<IngestRequest>;
}

pub struct OutboxedPublisher<P, O> {
    publisher: P,
    outbox: O,
}

impl<P, O> OutboxedPublisher<P, O> {
    pub fn new(publisher: P, outbox: O) -> Self {
        Self { publisher, outbox }
    }

    pub fn publisher(&self) -> &P {
        &self.publisher
    }

    pub fn outbox(&self) -> &O {
        &self.outbox
    }
}

impl<P, O> EventPublisher for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        match self.outbox.enqueue(event)? {
            EnqueueResult::AlreadyComplete => return Ok(()),
            EnqueueResult::AlreadyPending => {
                // A live request must never race a replay worker or another
                // request into a second fanout. Workers need a separate claim
                // API that atomically transfers ownership before publishing.
                return Err(GatewayError::new(
                    crate::GatewayErrorCode::IdempotencyInProgress,
                ));
            }
            EnqueueResult::Enqueued => {}
        }
        self.publisher.publish(event)?;
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        self.outbox.mark_complete(&key)
    }
}

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

    fn pending(&self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CountingPublisher(usize);

    impl EventPublisher for CountingPublisher {
        fn publish(&mut self, _event: &IngestRequest) -> Result<(), GatewayError> {
            self.0 += 1;
            Ok(())
        }
    }

    #[test]
    fn failed_fanout_leaves_event_pending_for_replay() {
        let mut outbox = InMemoryOutbox::new(4).unwrap();
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-8000-000000000001",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        assert_eq!(outbox.enqueue(&event).unwrap(), EnqueueResult::Enqueued);
        assert_eq!(
            outbox.enqueue(&event).unwrap(),
            EnqueueResult::AlreadyPending
        );
        assert_eq!(outbox.pending(), vec![event.clone()]);
        outbox
            .mark_complete(&OutboxKey {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
                event_id: event.event_id.clone(),
            })
            .unwrap();
        assert!(outbox.pending().is_empty());
        assert_eq!(
            outbox.enqueue(&event).unwrap(),
            EnqueueResult::AlreadyComplete
        );
    }

    #[test]
    fn live_publisher_does_not_republish_already_pending_event() {
        let mut outboxed = OutboxedPublisher::new(
            CountingPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        );
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-0000-000000000001",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        outboxed
            .outbox
            .enqueue(&event)
            .expect("seed pending outbox row");
        let error = outboxed.publish(&event).unwrap_err();
        assert_eq!(error.code, crate::GatewayErrorCode::IdempotencyInProgress);
        assert_eq!(outboxed.publisher.0, 0);
    }
}
