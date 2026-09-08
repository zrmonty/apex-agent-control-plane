//! Real-kernel OFD lifetime: a pre-exec child can retain a CLOEXEC duplicate.
use super::*;
use rustix::{fs::FlockOperation, io::Errno};

#[test]
fn task4y_journal_drop_releases_lock_with_retained_duplicate_without_unlocking_successor() {
    let root = std::path::PathBuf::from("/root")
        .join(format!("task4y-journal-lifetime-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(&root).unwrap();
    // Same open-file description as fork inheritance; held through owner drop.
    let inherited = journal._lock.try_clone().unwrap();
    let contender = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("owner.lock"))
        .unwrap();
    let attempt = || rustix::fs::flock(&contender, FlockOperation::NonBlockingLockExclusive);
    let live = attempt();
    eprintln!(
        "TASK4Y live-owner raw flock errno={:?}",
        live.as_ref().err().map(|e| e.raw_os_error())
    );
    assert_eq!(live, Err(Errno::WOULDBLOCK));
    assert!(matches!(Journal::open(&root), Err("RUNTIME_JOURNAL_BUSY")));
    drop(journal);
    let after_drop = attempt();
    eprintln!(
        "TASK4Y owner-dropped duplicate-retained raw flock errno={:?}",
        after_drop.as_ref().err().map(|e| e.raw_os_error())
    );
    if after_drop.is_ok() {
        rustix::fs::flock(&contender, FlockOperation::Unlock).unwrap();
    }
    let successor = Journal::open(&root);
    // Dispose of the retained old description before asserting, even on RED.
    drop(inherited);
    assert_eq!(
        after_drop,
        Ok(()),
        "owner drop must end its lock despite a retained duplicate"
    );
    let successor = successor.expect("immediate reopen while old duplicate remains");
    assert_eq!(
        attempt(),
        Err(Errno::WOULDBLOCK),
        "closing the old duplicate must not unlock the new owner"
    );
    drop(successor);
    assert_eq!(attempt(), Ok(()));
    rustix::fs::flock(&contender, FlockOperation::Unlock).unwrap();
    drop(contender);
    fs::remove_file(root.join("owner.lock")).unwrap();
    fs::remove_dir(root).unwrap();
}
