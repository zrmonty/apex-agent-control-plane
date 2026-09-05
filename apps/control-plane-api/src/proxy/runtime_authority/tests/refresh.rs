//! Real fixed-path reader tests; synthetic policy is NOT TLS or PG evidence.
use super::super::{
    RuntimeAuthorityError, RuntimeAuthorityPolicyFiles,
    lifecycle::{Shared, check_elapsed},
    refresh::{self, Reader},
};
use super::{
    material::Fixture,
    support::{bytes, enrollment, peer_policy},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

struct Running {
    shared: Arc<Shared>,
    reader: Option<Reader>,
}

impl Running {
    fn start(fixture: &Fixture) -> Self {
        let shared = Arc::new(Shared::new());
        let files = RuntimeAuthorityPolicyFiles::new(
            fixture.base(),
            "peer.json".into(),
            "enrollment.json".into(),
        )
        .unwrap();
        let reader = refresh::spawn(files, Arc::clone(&shared)).expect("one owned reader");
        Self {
            shared,
            reader: Some(reader),
        }
    }
    fn initial(&self) -> Result<(), RuntimeAuthorityError> {
        self.reader
            .as_ref()
            .unwrap()
            .initial
            .recv_timeout(Duration::from_secs(3))
            .expect("bounded initial observation")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shared.stop();
        if let Some(reader) = self.reader.take() {
            let until = Instant::now() + Duration::from_secs(3);
            while !reader.handle.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(reader.handle.is_finished(), "owned reader actually exits");
            reader.handle.join().expect("reader did not panic");
        }
    }
}

fn write_pair(fixture: &Fixture) {
    // Wide explicit component interval, not production policy defaults.
    for (name, mut value) in [
        ("peer.json", peer_policy()),
        ("enrollment.json", enrollment()),
    ] {
        value["validFromUnixUs"] = "1".into();
        value["expiresAtUnixUs"] = u64::MAX.to_string().into();
        fixture.write(name, &bytes(&value));
    }
}

fn eventually(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < until, "bounded reader transition");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn reader_publishes_initial_pair_and_identical_refresh_keeps_generation_fresh() {
    let fixture = Fixture::new();
    write_pair(&fixture);
    let running = Running::start(&fixture);
    running.initial().unwrap();
    let selected = running.shared.current().expect("initial pair");
    std::thread::sleep(Duration::from_millis(2200));
    assert!(Arc::ptr_eq(
        &selected,
        &running.shared.current().expect("refreshed, not stale")
    ));
}

#[test]
fn reader_invalidates_missing_file_and_recovery_has_new_generation() {
    let fixture = Fixture::new();
    write_pair(&fixture);
    let running = Running::start(&fixture);
    running.initial().unwrap();
    let old = running.shared.current().unwrap();
    std::fs::remove_file(fixture.base().join("enrollment.json")).unwrap();
    eventually(|| running.shared.current().is_err());
    write_pair(&fixture);
    eventually(|| {
        running
            .shared
            .current()
            .is_ok_and(|current| current.generation != old.generation)
    });
}

#[test]
fn reader_rejects_expired_initial_documents_and_retains_join_ownership() {
    let fixture = Fixture::new();
    fixture.write("peer.json", &bytes(&peer_policy()));
    fixture.write("enrollment.json", &bytes(&enrollment()));
    let running = Running::start(&fixture);
    assert_eq!(running.initial(), Err(RuntimeAuthorityError::Unavailable));
    assert!(running.shared.current().is_err());
}

#[test]
fn reader_checks_each_documents_wall_time_independently() {
    for file in ["peer.json", "enrollment.json"] {
        for future in [false, true] {
            let fixture = Fixture::new();
            write_pair(&fixture);
            let mut value = if file == "peer.json" {
                peer_policy()
            } else {
                enrollment()
            };
            if future {
                value["validFromUnixUs"] = (u64::MAX - 1).to_string().into();
                value["expiresAtUnixUs"] = u64::MAX.to_string().into();
            }
            fixture.write(file, &bytes(&value));
            let running = Running::start(&fixture);
            assert_eq!(running.initial(), Err(RuntimeAuthorityError::Unavailable));
            assert!(running.shared.current().is_err());
        }
    }
}

#[test]
fn stop_refuses_current_metadata_immediately() {
    let fixture = Fixture::new();
    write_pair(&fixture);
    let running = Running::start(&fixture);
    running.initial().unwrap();
    assert!(running.shared.current().is_ok());
    running.shared.stop();
    assert!(running.shared.current().is_err());
}

#[test]
fn elapsed_budget_has_positive_control_and_refuses_zero_expired_and_future_start() {
    let now = Instant::now();
    assert_eq!(check_elapsed(now, Duration::from_secs(5)), Ok(()));
    for (start, budget) in [
        (now, Duration::ZERO),
        (now - Duration::from_secs(5), Duration::from_secs(5)),
        (now + Duration::from_secs(1), Duration::from_secs(5)),
    ] {
        assert_eq!(
            check_elapsed(start, budget),
            Err(RuntimeAuthorityError::Deadline)
        );
    }
}
