//! Genuine Journal interleavings; the hook schedules but never supplies history.
use super::*;
use std::{
    cell::RefCell,
    sync::{TryLockError, mpsc},
    time::Duration,
};

struct ReadPause {
    sampled: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}
thread_local! {
    static READ_PAUSE: RefCell<Option<ReadPause>> = const { RefCell::new(None) };
}
pub(in crate::execution::journal::topology) fn after_entries() {
    if let Some(pause) = READ_PAUSE.with_borrow_mut(Option::take) {
        pause.sampled.send(()).unwrap();
        pause.resume.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

fn attach_second(j: &Journal, first: &Installed, d: &Document) -> (Installed, Document) {
    let c = NetworkCatalog::parse(d.topology.0.selected_catalog_json.as_bytes()).unwrap();
    let mut request = first.original.clone();
    let target = request.target.as_mut().unwrap();
    target.proxy_id = uuid::Uuid::now_v7().to_string();
    target.revision_id = uuid::Uuid::now_v7().to_string();
    request.operation_id = uuid::Uuid::now_v7().to_string();
    request.command_id = uuid::Uuid::now_v7().to_string();
    let mut record = Record::select(c.installation_id(), &request, None).unwrap();
    let mut i = first.clone();
    i.original = request;
    i.instance = record.instance.clone();
    i.network = None;
    let mut launch: proto::RuntimeLaunchContext = serde_json::from_str(&i.launch_json).unwrap();
    launch.target = i.original.target.clone();
    launch.process_instance_id = i.instance.clone();
    i.launch_json = serde_json::to_string(&launch).unwrap();
    let mut authority: serde_json::Value = serde_json::from_str(&i.authority_json).unwrap();
    authority["profile"]["proxy_id"] = json!(i.original.target.as_ref().unwrap().proxy_id);
    i.authority_json = authority.to_string();
    i.network = Some(j.reserve_network(&c, c.installation_id(), &i).unwrap());
    record.installed = Some(i.clone());
    j.save(&record).unwrap();
    let topology = Topology::new(&c, c.installation_id(), &i, "c".repeat(64), 1).unwrap();
    (i, Document::prepared(topology).unwrap())
}

#[test]
fn concurrent_valid_sidecar_never_poisons_catalog_free_history() {
    let (root, j, first, original) = setup();
    let installation = &original.topology.0.installation;
    let (sampled_tx, sampled_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let (second, next, read_result) = std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            READ_PAUSE.with_borrow_mut(|p| {
                *p = Some(ReadPause {
                    sampled: sampled_tx,
                    resume: resume_rx,
                });
            });
            j.network_reserved(installation, &first)
        });
        sampled_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // This lock observation only chooses a deterministic schedule. Results
        // below come from real protected records, global entries and sidecars.
        let serialized = match j.topology_lock.try_lock() {
            Ok(guard) => {
                drop(guard);
                false
            }
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Poisoned(_)) => panic!("unexpected mutex poison"),
        };
        let (second, next) = attach_second(&j, &first, &original);
        let writer_journal = &j;
        let writer_document = next.clone();
        let writer = scope.spawn(move || writer_journal.prepare_topology(&writer_document));
        // Old reader permits the genuine writer to finish before its scan.
        // Fixed reader holds the writer's lock, so it must finish first.
        let read_result = if serialized {
            resume_tx.send(()).unwrap();
            let result = reader.join().unwrap();
            writer.join().unwrap().unwrap();
            result
        } else {
            writer.join().unwrap().unwrap();
            resume_tx.send(()).unwrap();
            reader.join().unwrap()
        };
        eprintln!("sample_serialized={serialized} reader={read_result:?}");
        (second, next, read_result)
    });
    assert_eq!(
        read_result,
        Ok(true),
        "valid concurrent history must not quarantine"
    );
    assert_eq!(j.network_reserved(installation, &second), Ok(true));
    let all = j.topology_history(installation).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[&second.instance].topology_hash, next.topology_hash);
    assert_ne!(
        first.network.as_ref().unwrap().slot,
        second.network.as_ref().unwrap().slot
    );
    drop(j);
    let reopened = Journal::open(&root.0).unwrap();
    assert_eq!(reopened.network_reserved(installation, &first), Ok(true));
    assert_eq!(reopened.network_reserved(installation, &second), Ok(true));
    assert_eq!(reopened.topology_history(installation).unwrap().len(), 2);
}

#[test]
fn wrong_installation_does_not_poison_existing_sidecars() {
    let (_root, j, i, d) = setup();
    assert!(
        j.topology_history(&uuid::Uuid::now_v7().to_string())
            .is_err()
    );
    assert_eq!(j.network_reserved(&d.topology.0.installation, &i), Ok(true));
    assert_eq!(
        j.topology_history(&d.topology.0.installation)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn corrupted_global_history_stays_poisoned_after_restoring_valid_bytes() {
    let (root, j, i, d) = setup();
    let path = root.0.join("network-reservations.json");
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"[]").unwrap();
    assert!(j.topology_history(&d.topology.0.installation).is_err());
    fs::write(&path, original).unwrap();
    assert!(j.network_reserved(&d.topology.0.installation, &i).is_err());
    assert!(j.topology_history(&d.topology.0.installation).is_err());
}
