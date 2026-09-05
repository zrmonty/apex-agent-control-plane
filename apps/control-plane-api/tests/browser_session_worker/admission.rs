//! Public facade: real worker-owned PG admission, not HTTP/provider acceptance.
use super::*;
use apex_control_plane_api::browser::errors::BrowserError;

fn debt(client: &mut Client) -> (i64, i64) {
    let row = client
        .query_one(
            "SELECT tat_us,clock_us FROM apex_browser_login_admission WHERE singleton=1",
            &[],
        )
        .unwrap();
    (row.get(0), row.get(1))
}

#[test]
fn facade_admission_commits_before_returning_database_anchored_receipt() {
    let database = Database::new();
    let store = BrowserSessionStore::connect(&database.url).unwrap();
    let mut observer = observer(&database);
    let receipt = runtime().block_on(store.admit_login()).unwrap();
    let (tat, clock) = debt(&mut observer);
    assert!(
        clock > 0,
        "facade must actually commit admission, not return a local receipt"
    );
    assert_eq!(tat - clock, 1_000_000);
    assert_eq!(receipt.expires_at, clock / 1_000_000 + 600);
    runtime().block_on(store.shutdown()).unwrap();
}

#[test]
fn independent_facades_preserve_admission_debt_across_shutdown_and_reopen() {
    let database = Database::new();
    let first = BrowserSessionStore::connect(&database.url).unwrap();
    let second = BrowserSessionStore::connect(&database.url).unwrap();
    let mut observer = observer(&database);
    let runtime = runtime();
    runtime.block_on(first.admit_login()).unwrap();
    let before = debt(&mut observer);
    assert!(before.0 > 0, "the first facade must leave durable debt");
    runtime.block_on(first.shutdown()).unwrap();
    let reopened = BrowserSessionStore::connect(&database.url).unwrap();
    assert_eq!(
        debt(&mut observer),
        before,
        "startup must not refill the singleton"
    );
    runtime.block_on(second.admit_login()).unwrap();
    assert!(debt(&mut observer).0 > before.0);
    runtime.block_on(second.shutdown()).unwrap();
    runtime.block_on(reopened.shutdown()).unwrap();
}

#[test]
fn unpolled_admission_and_shutdown_do_not_spend_quota() {
    let database = Database::new();
    let store = BrowserSessionStore::connect(&database.url).unwrap();
    let mut observer = observer(&database);
    let before = debt(&mut observer);
    runtime().block_on(async {
        drop(store.admit_login());
        store.shutdown().await.unwrap();
        assert!(matches!(
            store.admit_login().await,
            Err(BrowserError::Unavailable)
        ));
    });
    assert_eq!(debt(&mut observer), before);
}
