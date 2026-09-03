use crate::{EventPublisher, GatewayError, IngestRequest, PublishOutcome};

#[derive(Debug, Default)]
pub struct InMemoryPublisher {
    published_event_ids: Vec<String>,
}

impl InMemoryPublisher {
    pub fn published_event_ids(&self) -> &[String] {
        &self.published_event_ids
    }
}

impl EventPublisher for InMemoryPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        self.published_event_ids.push(event.event_id.clone());
        Ok(PublishOutcome::Published)
    }
}
