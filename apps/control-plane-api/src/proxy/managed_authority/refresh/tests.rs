//! Physical thread-lifetime tests with an explicitly private reader seam.
use super::*;

fn document() -> Vec<u8> {
    br#"{"schema_version":1,"version":"v1","valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807","profiles":[]}"#.to_vec()
}
#[test]
fn initial_read_precedes_publication_and_shutdown_joins_the_only_worker() {
    let mut owner = RefreshOwner::new().unwrap();
    assert!(owner.shared.current().is_err());
    owner
        .start_with(|| Ok(document()), Duration::from_secs(2))
        .unwrap();
    let selected = owner.shared.current().unwrap();
    owner.shared.recheck(&selected).unwrap();
    owner.shutdown().unwrap();
    assert!(owner.handle.is_none());
    assert!(owner.shared.recheck(&selected).is_err());
    assert!(
        owner
            .start_with(|| Ok(document()), Duration::from_secs(1))
            .is_err()
    );
}
#[test]
fn startup_timeout_retains_physical_thread_and_cannot_mint_a_replacement() {
    let mut owner = RefreshOwner::new().unwrap();
    let (release, held) = mpsc::sync_channel(1);
    let (entered, observed) = mpsc::sync_channel(1);
    let result = owner.start_with(
        move || {
            entered.send(()).unwrap();
            held.recv().unwrap();
            Ok(document())
        },
        Duration::from_millis(25),
    );
    assert!(result.is_err());
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!owner.handle.as_ref().unwrap().is_finished());
    assert!(owner.shared.current().is_err());
    assert!(
        owner
            .start_with(
                || panic!("replacement must not run"),
                Duration::from_secs(1)
            )
            .is_err()
    );
    release.send(()).unwrap();
    owner.shutdown().unwrap();
    assert!(owner.handle.is_none());
    assert!(owner.shared.current().is_err());
}

#[tokio::test]
async fn cannot_construct_a_physical_root_owner_inside_tokio() {
    assert!(RefreshOwner::new().is_err());
}
