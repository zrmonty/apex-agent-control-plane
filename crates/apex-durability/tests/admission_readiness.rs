use apex_durability::{
    EventOutbox, EventPublisher, FileIdempotencyStore, FileOutbox, GatewayError, IdempotencyKey,
    IdempotencyStore, InMemoryIdempotencyStore, InMemoryOutbox, IngestRequest, OutboxedPublisher,
    PublishOutcome, ReservationResult, SharedOutbox,
};
use std::{fs, path::PathBuf};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "apex-readiness-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // This guard owns only the fresh directory created above, never a supplied path.
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key(id: u8) -> IdempotencyKey {
    IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: format!("01992000-0000-7000-8000-{id:012}"),
    }
}
fn event(id: u8) -> IngestRequest {
    let key = key(id);
    IngestRequest {
        workspace_id: key.workspace_id,
        namespace_id: key.namespace_id,
        event_id: key.event_id,
        scope_key: "acme/prod".into(),
        envelope: vec![id],
    }
}

#[test]
fn admission_readiness_checks_real_idempotency_without_changing_journal_or_reservations() {
    let dir = Directory::new();
    let path = dir.0.join("idempotency.jsonl");
    let mut store = FileIdempotencyStore::open(&path, &dir.0, 2).unwrap();
    let before = fs::read(&path).unwrap();
    for _ in 0..4 {
        store.check_admission_readiness("acme", "prod").unwrap();
    }
    assert_eq!(fs::read(&path).unwrap(), before);
    for id in 1..=2 {
        assert!(matches!(
            store.reserve(key(id), [id; 32]).unwrap(),
            ReservationResult::Reserved(_)
        ));
    }
    assert!(store.check_admission_readiness("acme", "prod").is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn admission_readiness_checks_real_outbox_without_enqueueing_or_consuming_capacity() {
    let dir = Directory::new();
    let path = dir.0.join("outbox.jsonl");
    let mut store = FileOutbox::open(&path, &dir.0, 2).unwrap();
    let before = fs::read(&path).unwrap();
    for _ in 0..4 {
        store.check_admission_readiness("acme", "prod").unwrap();
    }
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(store.pending_count().unwrap(), 0);
    store.enqueue(&event(1)).unwrap();
    store.enqueue(&event(2)).unwrap();
    let full = fs::read(&path).unwrap();
    assert!(store.check_admission_readiness("acme", "prod").is_err());
    assert_eq!(store.pending_count().unwrap(), 2);
    assert_eq!(fs::read(&path).unwrap(), full);
}

#[test]
fn admission_readiness_never_treats_memory_as_durable_storage() {
    assert!(
        InMemoryIdempotencyStore::new(2)
            .unwrap()
            .check_admission_readiness("acme", "prod")
            .is_err()
    );
    assert!(
        InMemoryOutbox::new(2)
            .unwrap()
            .check_admission_readiness("acme", "prod")
            .is_err()
    );
}

struct NoFanout;
impl EventPublisher for NoFanout {
    fn publish(&mut self, _: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        panic!("readiness must never invoke downstream fanout");
    }
}

#[test]
fn admission_readiness_reaches_the_real_boxed_shared_outbox_without_fanout() {
    let dir = Directory::new();
    let path = dir.0.join("outbox.jsonl");
    let shared = SharedOutbox::new(Box::new(FileOutbox::open(&path, &dir.0, 2).unwrap()));
    let mut writer = shared.clone();
    let outbox: Box<dyn EventOutbox> = Box::new(shared);
    let mut publisher = OutboxedPublisher::new(NoFanout, outbox);
    assert!(NoFanout.check_admission_readiness("acme", "prod").is_err());
    publisher.check_admission_readiness("acme", "prod").unwrap();
    assert!(fs::read(&path).unwrap().is_empty());
    writer.enqueue(&event(1)).unwrap();
    writer.enqueue(&event(2)).unwrap();
    assert!(publisher.check_admission_readiness("acme", "prod").is_err());
    assert_eq!(writer.pending_count().unwrap(), 2);
}

#[test]
fn admission_readiness_enforces_scoped_capacity_and_rejects_malformed_scope() {
    let dir = Directory::new();
    let mut store =
        FileIdempotencyStore::open(&dir.0.join("idempotency.jsonl"), &dir.0, 32).unwrap();
    for id in 1..=2 {
        let ReservationResult::Reserved(reservation) = store.reserve(key(id), [id; 32]).unwrap()
        else {
            panic!()
        };
        if id == 1 {
            store.commit(reservation).unwrap();
        }
    }
    assert!(store.check_admission_readiness("acme", "prod").is_err());
    store.check_admission_readiness("other", "prod").unwrap();
    let mut outbox = FileOutbox::open(&dir.0.join("outbox.jsonl"), &dir.0, 32).unwrap();
    for (workspace, namespace) in [("", "prod"), ("acme", "../prod"), ("acme/prod", "prod")] {
        assert!(
            store
                .check_admission_readiness(workspace, namespace)
                .is_err()
        );
        assert!(
            outbox
                .check_admission_readiness(workspace, namespace)
                .is_err()
        );
    }
}

#[test]
fn admission_readiness_refuses_readonly_journals_without_modifying_them() {
    let dir = Directory::new();
    let id_path = dir.0.join("idempotency.jsonl");
    let out_path = dir.0.join("outbox.jsonl");
    let mut idempotency = FileIdempotencyStore::open(&id_path, &dir.0, 2).unwrap();
    let mut outbox = FileOutbox::open(&out_path, &dir.0, 2).unwrap();
    for path in [&id_path, &out_path] {
        let original = fs::metadata(path).unwrap().permissions();
        let mut readonly = original.clone();
        readonly.set_readonly(true);
        fs::set_permissions(path, readonly).unwrap();
        let refused = if path == &id_path {
            idempotency
                .check_admission_readiness("acme", "prod")
                .is_err()
        } else {
            outbox.check_admission_readiness("acme", "prod").is_err()
        };
        fs::set_permissions(path, original).unwrap();
        assert!(refused);
        assert!(fs::read(path).unwrap().is_empty());
    }
}

#[test]
fn admission_readiness_shared_lock_contention_never_waits_for_an_admission_write() {
    use std::sync::mpsc;
    use std::time::Duration;
    struct HeldWrite {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl EventOutbox for HeldWrite {
        fn enqueue(
            &mut self,
            _: &IngestRequest,
        ) -> Result<apex_durability::EnqueueResult, GatewayError> {
            self.started.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(apex_durability::EnqueueResult::Enqueued)
        }
        fn mark_complete(&mut self, _: &apex_durability::OutboxKey) -> Result<(), GatewayError> {
            unreachable!()
        }
        fn pending(&mut self) -> Vec<IngestRequest> {
            unreachable!()
        }
    }
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut writer = SharedOutbox::new(Box::new(HeldWrite {
        started: started_tx,
        release: release_rx,
    }));
    let mut observer = writer.clone();
    let writer = std::thread::spawn(move || writer.enqueue(&event(1)).unwrap());
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let (result_tx, result_rx) = mpsc::channel();
    let probe = std::thread::spawn(move || {
        result_tx
            .send(observer.check_admission_readiness("acme", "prod"))
            .unwrap()
    });
    let result = result_rx.recv_timeout(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    probe.join().unwrap();
    assert_eq!(
        result.unwrap().unwrap_err().code,
        apex_durability::GatewayErrorCode::AdmissionBusy
    );
}
