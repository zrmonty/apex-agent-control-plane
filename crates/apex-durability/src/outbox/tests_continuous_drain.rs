/// Phase 0.6 item 4 (continuous drain): `PendingEventReplayer::replay_pending`
/// now returns whether it actually settled work, which is the signal
/// `spawn_fanout_worker` uses to decide whether to loop again immediately or
/// fall back to sleeping `interval`. These three cases pin the contract at the
/// `OutboxedPublisher` level, independent of the worker loop itself.
mod continuous_drain_signal {
    use super::*;
    use crate::outbox::PendingEventReplayer;

    #[test]
    fn empty_outbox_reports_no_work_done() {
        let mut outboxed = OutboxedPublisher::new(
            CountingPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        );
        assert!(
            !outboxed.replay_pending().unwrap(),
            "nothing pending must not signal a drain-again cycle"
        );
    }

    #[test]
    fn a_settled_event_reports_work_done() {
        let mut outboxed = OutboxedPublisher::new(
            CountingPublisher::default(),
            InMemoryOutbox::new(4).unwrap(),
        );
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-0000-0000000000c1",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        outboxed.publish(&event).expect("durably enqueue");
        assert!(
            outboxed.replay_pending().unwrap(),
            "a cycle that durably settles an event must signal more draining may be worthwhile"
        );
        // A second cycle over an outbox with nothing left pending goes back
        // to reporting no work, not a stale "true" from the previous cycle.
        assert!(!outboxed.replay_pending().unwrap());
    }

    #[test]
    fn a_cycle_where_every_row_fails_reports_no_work_done() {
        let event = IngestRequest::new(
            "018f5c91-2d88-7c00-0000-0000000000c2",
            "acme",
            "prod",
            b"payload".to_vec(),
        );
        let mut outbox = InMemoryOutbox::new(4).unwrap();
        outbox.enqueue(&event).unwrap();
        let mut outboxed = OutboxedPublisher::new(AlwaysFailingPublisher::default(), outbox);
        // Rows were claimed (pending was non-empty) but nothing settled --
        // this must report `false` exactly like the empty case, so
        // `spawn_fanout_worker` falls back to its `interval` throttle instead
        // of spinning against a sink that is still down.
        assert!(
            !outboxed.replay_pending().unwrap(),
            "a cycle that claims rows but settles none of them must not signal continuous drain"
        );
        assert_eq!(outboxed.publisher().0, 1);
    }
}
