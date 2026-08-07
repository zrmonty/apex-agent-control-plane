use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{EventPublisher, GatewayError, IngestRequest, PublishOutcome};

pub struct OutboxedPublisher<P, O> {
    pub(crate) publisher: P,
    pub(crate) outbox: O,
}

pub trait PendingEventReplayer {
    fn replay_pending(&mut self) -> Result<(), GatewayError>;
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

    pub fn outbox_mut(&mut self) -> &mut O {
        &mut self.outbox
    }
}

impl<P, O> OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    /// Replays rows that were durably enqueued before a previous process
    /// stopped. This must run before the live server accepts traffic so a
    /// pending row cannot be mistaken for a successful duplicate.
    fn replay_pending_inner(&mut self) -> Result<(), GatewayError> {
        for event in self.outbox.pending() {
            // The outcome is not meaningful here: `self.publisher` is the
            // fanout, not another outbox, so it always reports Published.
            let _ = self.publisher.publish(&event)?;
            let key = OutboxKey {
                workspace_id: event.workspace_id.clone(),
                namespace_id: event.namespace_id.clone(),
                event_id: event.event_id.clone(),
            };
            self.outbox.mark_complete(&key)?;
        }
        Ok(())
    }
}

impl<P, O> PendingEventReplayer for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn replay_pending(&mut self) -> Result<(), GatewayError> {
        self.replay_pending_inner()
    }
}

impl<P, O> EventPublisher for OutboxedPublisher<P, O>
where
    P: EventPublisher,
    O: EventOutbox,
{
    fn can_reconcile_commit_failure(&self) -> bool {
        true
    }

    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        match self.outbox.enqueue(event)? {
            // The outbox already holds a completed row for this exact payload
            // (post-9734d9a `AlreadyComplete` is fingerprint-matched, so this
            // really is the same event, not merely the same id). Say so
            // instead of returning a bare Ok that the caller cannot tell apart
            // from a fresh publish.
            EnqueueResult::AlreadyComplete => return Ok(PublishOutcome::AlreadyComplete),
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
        self.outbox.mark_complete(&key)?;
        Ok(PublishOutcome::Published)
    }
}
