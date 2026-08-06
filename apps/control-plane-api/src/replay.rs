//! Best-effort, retrying fanout of durably accepted commands to the primary
//! trace (JetStream/ClickHouse, via an `apex_event_ingest::EventPublisher`).
//!
//! This worker is intentionally decoupled from the accept path
//! ([`crate::outbox::submit_command`]): a command is durable the moment the
//! outbox commits it, and this loop is what eventually delivers it once the
//! primary data path is reachable again. A stopped or degraded publisher
//! only delays `delivered = true`; it never loses or re-orders-into-loss a
//! command, and it never blocks a new `SubmitCommand` call.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use apex_event_ingest::{EventPublisher, OutboxKey};

use crate::outbox::ControlOutboxBackend;

/// Spawns a loop that periodically drains pending outbox rows through
/// `publisher` and marks each complete on success. Failures are logged and
/// retried on the next interval; they never panic the worker or affect the
/// accept path.
pub fn spawn_fanout_worker<P>(
    backend: Arc<ControlOutboxBackend>,
    publisher: Arc<tokio::sync::Mutex<P>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
where
    P: EventPublisher + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let backend = backend.clone();
            let pending = match backend.with_lock(|outbox| outbox.pending()) {
                Ok(pending) => pending,
                Err(_) => continue,
            };
            if pending.is_empty() {
                continue;
            }
            let mut publisher_guard = publisher.lock().await;
            for event in pending {
                let publish_result = catch_unwind(AssertUnwindSafe(|| {
                    publisher_guard.publish(&event)
                }));
                match publish_result {
                    Ok(Ok(())) => {
                        let key = OutboxKey {
                            workspace_id: event.workspace_id().to_owned(),
                            namespace_id: event.namespace_id().to_owned(),
                            event_id: event.event_id().to_owned(),
                        };
                        let _ = backend.with_lock(|outbox| outbox.mark_complete(&key));
                    }
                    Ok(Err(error)) => {
                        eprintln!(
                            "control-plane-api fanout deferred: {}: {}",
                            error.code.public_code(),
                            error.summary
                        );
                    }
                    Err(_) => {
                        eprintln!("control-plane-api fanout deferred: panic during publish");
                    }
                }
            }
        }
    })
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use apex_event_ingest::{GatewayError, InMemoryOutbox};

    use super::*;

    struct FlakyPublisher {
        fail_next: bool,
        published: Vec<String>,
    }

    impl EventPublisher for FlakyPublisher {
        fn publish(&mut self, event: &apex_event_ingest::IngestRequest) -> Result<(), GatewayError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(GatewayError::publish_failed());
            }
            self.published.push(event.event_id().to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn fanout_worker_retries_after_a_transient_publish_failure() {
        let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> =
            Box::new(InMemoryOutbox::new(16).unwrap());
        let backend = Arc::new(ControlOutboxBackend::new(outbox));
        let request = apex_event_ingest::IngestRequest::new(
            "018f0000-0000-7000-8000-000000000000",
            "acme",
            "prod",
            vec![1, 2, 3],
        );
        backend
            .with_lock(|outbox| outbox.enqueue(&request))
            .unwrap()
            .unwrap();

        let publisher = Arc::new(tokio::sync::Mutex::new(FlakyPublisher {
            fail_next: true,
            published: vec![],
        }));
        let _handle = spawn_fanout_worker(backend.clone(), publisher.clone(), Duration::from_millis(5));

        // First tick: publish fails, row stays pending.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(publisher.lock().await.published.is_empty());

        // Second tick: publish succeeds, row is marked complete.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(publisher.lock().await.published.len(), 1);
        let remaining = backend.with_lock(|outbox| outbox.pending()).unwrap();
        assert!(remaining.is_empty());
    }
}
