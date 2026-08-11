//! [`crate::inbox::ControlInboxBackend`] tests: the single-mutex
//! serialization guarantee across concurrent callers.

use crate::inbox::*;

use super::support::*;

/// A restarted or duplicated agent process polling concurrently must not
/// both receive the same command. The backend's single mutex is what makes
/// that true, so this drives it through the backend rather than the raw
/// inbox.
#[test]
fn concurrent_polls_never_hand_one_command_to_two_callers() {
    use std::sync::Arc;

    let backend = Arc::new(ControlInboxBackend::new(Box::new(
        InMemoryCommandInbox::new(64, 64),
    )));
    backend
        .with_lock(|inbox| inbox.record(&command("cmd-1", "agent-a")))
        .unwrap()
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let backend = Arc::clone(&backend);
        handles.push(std::thread::spawn(move || {
            backend
                .with_lock(|inbox| {
                    inbox.claim(
                        &target("agent-a"),
                        &acme_prod(),
                        DeliveryPolicy::default(),
                        5_000,
                    )
                })
                .unwrap()
                .unwrap()
                .len()
        }));
    }
    let total: usize = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .sum();
    assert_eq!(
        total, 1,
        "exactly one concurrent poll may receive the command"
    );
}
