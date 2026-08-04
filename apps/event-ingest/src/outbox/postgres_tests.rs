#![cfg(all(test, feature = "postgres"))]

use super::postgres::PostgresOutbox;
use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::IngestRequest;

fn url() -> Option<String> {
    std::env::var("APEX_POSTGRES_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

#[test]
fn postgres_outbox_enqueue_complete_and_replay() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut outbox = PostgresOutbox::connect(&url, 64).expect("connect");
    let event_id = "018f5c91-2d88-7c00-8000-0000000000e2";
    let event = IngestRequest::new(event_id, "acme", "prod", b"canonical-envelope".to_vec());
    let _ = outbox.enqueue(&event);
    match outbox.enqueue(&event).unwrap() {
        EnqueueResult::Enqueued | EnqueueResult::AlreadyPending => {}
        EnqueueResult::AlreadyComplete => return,
    }
    let pending = outbox.pending();
    assert!(pending.iter().any(|e| e.event_id == event_id));
    outbox
        .mark_complete(&OutboxKey {
            workspace_id: "acme".into(),
            namespace_id: "prod".into(),
            event_id: event_id.into(),
        })
        .unwrap();
    assert_eq!(
        outbox.enqueue(&event).unwrap(),
        EnqueueResult::AlreadyComplete
    );
}
