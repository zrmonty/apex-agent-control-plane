use super::*;
use std::sync::mpsc;

#[test]
fn managed_evidence_owner_first_publication_poison_and_shutdown() {
    let initial = super::super::tests::document(&super::super::tests::enrollment(
        "agent-a",
        "000000000001",
        &format!("{:x}", Sha256::digest(b"token-a")),
        &"bb".repeat(32),
    ));
    let (replacement, updates) = mpsc::channel();
    let mut bytes = Some(initial);
    let (owner, resolver) = ManagedEvidenceOwner::start_reader(move || {
        if let Some(bytes) = bytes.take() {
            return Ok(bytes);
        }
        updates
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or(Err(EnrollmentError))
    })
    .expect("first valid publication before returning owner");
    let peer = PeerIdentity {
        certificate_sha256: [0xbb; 32],
    };
    assert!(resolver.resolve_with_peer("token-a", Some(&peer)).is_ok());
    replacement.send(Err(EnrollmentError)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while resolver.resolve_with_peer("token-a", Some(&peer)).is_ok() {
        assert!(Instant::now() < deadline, "invalid replacement must poison");
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(owner);
    assert!(resolver.resolve_with_peer("token-a", Some(&peer)).is_err());
}

#[test]
fn managed_evidence_held_read_refuses_stale_requests_and_shutdown_keeps_owner() {
    let initial = super::super::tests::document(&super::super::tests::enrollment(
        "agent-a",
        "000000000001",
        &format!("{:x}", Sha256::digest(b"token-a")),
        &"bb".repeat(32),
    ));
    let (entered, started) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let mut first = true;
    let (owner, resolver) = ManagedEvidenceOwner::start_reader(move || {
        if first {
            first = false;
            return Ok(initial.clone());
        }
        entered.send(()).unwrap();
        held.recv_timeout(Duration::from_secs(15))
            .map_err(|_| EnrollmentError)?;
        Ok(initial.clone())
    })
    .unwrap();
    started.recv_timeout(Duration::from_secs(3)).unwrap();
    std::thread::sleep(Duration::from_secs(5));
    let peer = PeerIdentity {
        certificate_sha256: [0xbb; 32],
    };
    let request_started = Instant::now();
    assert!(resolver.resolve_with_peer("token-a", Some(&peer)).is_err());
    assert!(
        request_started.elapsed() < Duration::from_millis(100),
        "request must not wait for physical read"
    );
    let (finished, completion) = mpsc::channel();
    let root = std::thread::spawn(move || {
        drop(owner);
        finished.send(()).unwrap();
    });
    assert!(
        completion.recv_timeout(Duration::from_millis(100)).is_err(),
        "physical owner cannot be abandoned"
    );
    assert!(started.try_recv().is_err(), "no replacement reader");
    release.send(()).unwrap();
    completion.recv_timeout(Duration::from_secs(2)).unwrap();
    root.join().unwrap();
    assert!(resolver.resolve_with_peer("token-a", Some(&peer)).is_err());
}

#[test]
fn managed_evidence_first_read_is_owned_and_cannot_publish_after_freshness_limit() {
    let (entered, started) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let (returned, result) = mpsc::channel();
    let root = std::thread::spawn(move || {
        let outcome = ManagedEvidenceOwner::start_reader(move || {
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(15))
                .map_err(|_| EnrollmentError)?;
            Ok(super::super::tests::valid_document())
        });
        returned.send(outcome.is_err()).unwrap();
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(result.recv_timeout(Duration::from_millis(50)).is_err());
    std::thread::sleep(Duration::from_secs(5));
    release.send(()).unwrap();
    assert!(result.recv_timeout(Duration::from_secs(2)).unwrap());
    root.join().unwrap();
}

#[test]
fn managed_evidence_partial_construction_and_invalid_initial_read_join() {
    struct Lifetime(mpsc::Sender<()>);
    impl Drop for Lifetime {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let (done, joined) = mpsc::channel();
    let life = Lifetime(done);
    let result = ManagedEvidenceOwner::start_reader(move || {
        let _ = &life;
        Err(EnrollmentError)
    });
    assert!(result.is_err());
    joined.recv_timeout(Duration::from_secs(1)).unwrap();
    let (done, joined) = mpsc::channel();
    let life = Lifetime(done);
    let partial = || -> Result<(), EnrollmentError> {
        let (_owner, _resolver) = ManagedEvidenceOwner::start_reader(move || {
            let _ = &life;
            Ok(super::super::tests::valid_document())
        })?;
        Err(EnrollmentError)
    };
    assert!(partial().is_err());
    joined.recv_timeout(Duration::from_secs(1)).unwrap();
}
