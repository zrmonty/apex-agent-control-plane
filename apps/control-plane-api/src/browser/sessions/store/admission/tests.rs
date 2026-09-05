//! Real PG transactions with a private post-lock clock seam, not fake storage.
use super::*;
use postgres::{Client, NoTls};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[path = "../../../../../tests/browser_session_store/support.rs"]
mod database;
use database::Database;

const T: i64 = 1_800_000_000_250_000;
const WAIT: Duration = Duration::from_secs(6);

fn at(store: &mut PostgresSessionStore, now: i64) -> Result<LoginAdmission, BrowserError> {
    store.admit_with_clock(|_| Ok(now))
}

fn fresh() -> (Database, PostgresSessionStore) {
    let db = Database::new();
    let store = PostgresSessionStore::connect(&db.url).unwrap();
    (db, store)
}

fn debt(db: &Database) -> (i64, i64) {
    let row = db
        .client()
        .query_one(
            "SELECT tat_us,clock_us FROM apex_browser_login_admission WHERE singleton=1",
            &[],
        )
        .unwrap();
    (row.get(0), row.get(1))
}

fn drain(store: &mut PostgresSessionStore, now: i64) {
    for _ in 0..60 {
        at(store, now).expect("sixty admissions must fit the initial burst");
    }
}

#[test]
fn global_burst_and_exact_one_second_refill() {
    let (_db, mut store) = fresh();
    drain(&mut store, T);
    assert!(matches!(at(&mut store, T), Err(BrowserError::RateLimited)));
    assert!(matches!(
        at(&mut store, T + 999_999),
        Err(BrowserError::RateLimited)
    ));
    assert!(at(&mut store, T + 1_000_000).is_ok());
    assert!(matches!(
        at(&mut store, T + 1_000_000),
        Err(BrowserError::RateLimited)
    ));
}

#[test]
fn receipt_is_database_admission_anchored_and_debt_is_committed() {
    let (db, mut store) = fresh();
    let receipt = at(&mut store, T).unwrap();
    assert_eq!(receipt.expires_at, 1_800_000_600);
    assert_eq!(debt(&db), (1_800_000_001_250_000, T));
    assert_eq!(format!("{receipt:?}"), "LoginAdmission([REDACTED])");
}

#[test]
fn quota_denial_preserves_debt_and_backend_connection() {
    let (db, mut store) = fresh();
    drain(&mut store, T);
    let pid: i32 = store
        .client()
        .unwrap()
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let before = debt(&db);
    for _ in 0..3 {
        assert!(matches!(at(&mut store, T), Err(BrowserError::RateLimited)));
        let after: i32 = store
            .client()
            .unwrap()
            .query_one("SELECT pg_backend_pid()", &[])
            .unwrap()
            .get(0);
        assert_eq!(after, pid, "ordinary denial must not retire the connection");
        assert_eq!(
            debt(&db),
            before,
            "denial must not charge or move the clock fence"
        );
    }
}

#[test]
fn independent_pg_connections_share_exactly_sixty_admissions() {
    let (db, store) = fresh();
    drop(store);
    std::thread::scope(|scope| {
        let (ready, initialized) = mpsc::channel();
        let mut workers = Vec::new();
        let mut starts = Vec::new();
        for _ in 0..2 {
            let (start, begin) = mpsc::sync_channel(1);
            let ready = ready.clone();
            let url = &db.url;
            starts.push(start);
            workers.push(scope.spawn(move || {
                let mut store = PostgresSessionStore::connect(url).unwrap();
                ready.send(()).unwrap();
                begin.recv_timeout(WAIT).unwrap();
                let mut admitted = 0;
                for _ in 0..60 {
                    match at(&mut store, T) {
                        Ok(_) => admitted += 1,
                        Err(BrowserError::RateLimited) => {}
                        Err(error) => panic!("unexpected admission failure: {error:?}"),
                    }
                }
                admitted
            }));
        }
        drop(ready);
        for _ in 0..2 {
            initialized.recv_timeout(WAIT).unwrap();
        }
        for start in starts {
            start.send(()).unwrap();
        }
        let total: usize = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .sum();
        assert_eq!(total, 60, "quota belongs to the database, not a connection");
    });
    assert_eq!(debt(&db), (1_800_000_060_250_000, T));
}

#[test]
fn backward_clock_is_fenced_without_mutation() {
    let (db, mut store) = fresh();
    at(&mut store, T).unwrap();
    let before = debt(&db);
    assert!(matches!(
        at(&mut store, T - 1),
        Err(BrowserError::Unavailable)
    ));
    assert_eq!(debt(&db), before);
    drop(store);
    let mut reopened = PostgresSessionStore::connect(&db.url).unwrap();
    assert!(matches!(
        at(&mut reopened, T - 1),
        Err(BrowserError::Unavailable)
    ));
    assert_eq!(debt(&db), before);
}

#[test]
fn forward_jump_refills_only_one_burst() {
    let (_db, mut store) = fresh();
    drain(&mut store, T);
    drain(&mut store, T + 3_600_000_000);
    assert!(matches!(
        at(&mut store, T + 3_600_000_000),
        Err(BrowserError::RateLimited)
    ));
}

#[test]
fn negative_clock_is_rejected_without_mutation() {
    let (db, mut store) = fresh();
    assert!(matches!(at(&mut store, -1), Err(BrowserError::Unavailable)));
    assert_eq!(debt(&db), (0, 0));
}

#[test]
fn overflowing_clock_is_rejected_without_mutation() {
    let (db, mut store) = fresh();
    assert!(matches!(
        at(&mut store, i64::MAX),
        Err(BrowserError::Unavailable)
    ));
    assert_eq!(debt(&db), (0, 0));
}

#[test]
fn implausible_persisted_debt_is_not_reset() {
    let (db, mut store) = fresh();
    db.client()
        .execute(
            "UPDATE apex_browser_login_admission SET tat_us=$1,clock_us=$2",
            &[&(T + 60_000_001), &T],
        )
        .unwrap();
    let before = debt(&db);
    assert!(matches!(at(&mut store, T), Err(BrowserError::Unavailable)));
    assert_eq!(debt(&db), before);
}

#[test]
fn pruning_and_reopen_cannot_refill_exhausted_quota() {
    let (db, mut store) = fresh();
    db.client()
        .execute(
            "UPDATE apex_browser_login_admission SET tat_us=$1,clock_us=$2",
            &[&(T + 60_000_000), &T],
        )
        .unwrap();
    store.prune_expired().unwrap();
    drop(store);
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    assert_eq!(debt(&db), (T + 60_000_000, T));
    assert!(matches!(at(&mut store, T), Err(BrowserError::RateLimited)));
    assert_eq!(debt(&db), (T + 60_000_000, T));
}

#[test]
fn missing_singleton_is_not_recreated_by_admission() {
    let (db, mut store) = fresh();
    db.client()
        .execute("DELETE FROM apex_browser_login_admission", &[])
        .unwrap();
    assert!(matches!(at(&mut store, T), Err(BrowserError::Unavailable)));
    let count: i64 = db
        .client()
        .query_one("SELECT count(*) FROM apex_browser_login_admission", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[test]
fn clock_sampling_follows_row_lock_and_uses_read_committed() {
    let (db, store) = fresh();
    drop(store);
    let application = format!("admission_lock_{}", uuid::Uuid::now_v7().simple());
    let url = format!("{}&application_name={application}", db.url);
    let sample = Arc::new(AtomicI64::new(T));
    let called = Arc::new(AtomicI64::new(0));
    let mut observer = db.client();
    observer
        .batch_execute("SET statement_timeout='1s'")
        .unwrap();
    let mut locker = db.client();
    let pid: i32 = locker
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let mut lock = locker.transaction().unwrap();
    lock.query_one(
        "SELECT singleton FROM apex_browser_login_admission WHERE singleton=1 FOR UPDATE",
        &[],
    )
    .unwrap();
    std::thread::scope(|scope| {
        let sample_read = Arc::clone(&sample);
        let calls = Arc::clone(&called);
        let worker = scope.spawn(move || {
            let mut store = PostgresSessionStore::connect(&url).unwrap();
            store
                .client()
                .unwrap()
                .batch_execute("SET default_transaction_isolation='repeatable read'")
                .unwrap();
            store.admit_with_clock(|tx| {
                calls.fetch_add(1, Ordering::SeqCst);
                let isolation: String = tx
                    .query_one("SHOW transaction_isolation", &[])
                    .unwrap()
                    .get(0);
                assert_eq!(isolation, "read committed");
                Ok(sample_read.load(Ordering::SeqCst))
            })
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let blocked = loop {
            let waiting: bool = observer.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND $2=ANY(pg_blocking_pids(pid)))",
                &[&application, &pid],
            ).unwrap().get(0);
            if waiting || Instant::now() >= deadline {
                break waiting;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let early_samples = called.load(Ordering::SeqCst);
        sample.store(T + 2_000_000, Ordering::SeqCst);
        lock.commit().unwrap();
        let result = worker.join().unwrap().unwrap();
        assert!(blocked, "admission must reach the held singleton row lock");
        assert_eq!(early_samples, 0, "clock sampled before acquiring the lock");
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert_eq!(result.expires_at, 1_800_000_602);
    });
}
