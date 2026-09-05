//! Real PostgreSQL construction/failure/drop/shutdown tests at the facade seam.

use super::*;
use apex_control_plane_api::browser::errors::BrowserError;
use tokio::sync::oneshot;

fn drop_before_first_poll(abort_task: bool) {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let store = BrowserSessionStore::connect(&connection_string).unwrap();
    let mut observer = observer(&database);
    assert_eq!(connection_count(&mut observer, &application_name), 1);
    runtime().block_on(async move {
        let parent = async move {
            store
                .take_login(
                    LookupDigest::from_bytes([1; 32]),
                    LookupDigest::from_bytes([2; 32]),
                )
                .await
        };
        if abort_task {
            // No yield between spawn and abort on a current-thread runtime.
            let task = tokio::spawn(parent);
            task.abort();
            let Err(error) = task.await else {
                panic!("parent must be cancelled before polling")
            };
            assert!(error.is_cancelled());
        } else {
            drop(parent);
        }
    });
    wait_closed(&mut observer, &application_name);
}

#[test]
fn real_postgres_drop_before_parent_first_poll_closes_the_idle_owner() {
    drop_before_first_poll(false);
}

#[test]
fn real_postgres_abort_before_first_poll_closes_the_idle_owner() {
    drop_before_first_poll(true);
}

#[test]
fn real_postgres_shutdown_closes_the_owner_while_clones_survive_and_refuses_new_work() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let store = BrowserSessionStore::connect(&connection_string).unwrap();
    let clone = store.clone();
    let mut observer = observer(&database);
    let runtime = runtime();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(6), store.shutdown())
            .await
            .expect("shutdown must finish within its deadline")
            .unwrap();
    });
    wait_closed(&mut observer, &application_name);
    runtime.block_on(async {
        assert_eq!(
            clone
                .create_login(login_attempt(
                    LookupDigest::from_bytes([1; 32]),
                    LookupDigest::from_bytes([2; 32])
                ))
                .await,
            Err(BrowserError::Unavailable)
        );
        assert!(matches!(
            store
                .take_login(
                    LookupDigest::from_bytes([1; 32]),
                    LookupDigest::from_bytes([2; 32])
                )
                .await,
            Err(BrowserError::Unavailable)
        ));
        clone.shutdown().await.unwrap();
    });
    assert_eq!(connection_count(&mut observer, &application_name), 0);
}

#[test]
fn real_postgres_failed_migration_closes_its_partially_constructed_owner() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let mut observer = observer(&database);
    observer
        .batch_execute(
            "CREATE TABLE apex_browser_session_schema(version INTEGER NOT NULL);
         INSERT INTO apex_browser_session_schema VALUES(3)",
        )
        .unwrap();
    let started_at = Instant::now();
    assert!(matches!(
        BrowserSessionStore::connect(&connection_string),
        Err(BrowserError::Unavailable)
    ));
    assert!(started_at.elapsed() < Duration::from_secs(6));
    wait_closed(&mut observer, &application_name);
    let row = observer
        .query_one(
            "SELECT to_regclass('apex_browser_sessions') IS NULL,
                to_regclass('apex_browser_login_attempts') IS NULL",
            &[],
        )
        .unwrap();
    assert!(row.get::<_, bool>(0) && row.get::<_, bool>(1));
}

#[test]
fn real_postgres_startup_from_tokio_is_refused_without_opening_a_connection() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let mut observer = observer(&database);
    runtime().block_on(async {
        let started_at = Instant::now();
        assert!(matches!(
            BrowserSessionStore::connect(&connection_string),
            Err(BrowserError::Unavailable)
        ));
        assert!(started_at.elapsed() < Duration::from_millis(100));
    });
    assert_eq!(connection_count(&mut observer, &application_name), 0);
}

fn wait_for_pg_sleep(observer: &mut Client, application_name: &str) {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let sleeping: bool = observer
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
             WHERE datname=current_database() AND application_name=$1
             AND state='active' AND wait_event='PgSleep')",
                &[&application_name],
            )
            .unwrap()
            .get(0);
        if sleeping {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "test must observe an actual PostgreSQL stall"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_postgres_abort_during_database_stall_drops_the_owner_without_blocking_tokio() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let store = BrowserSessionStore::connect(&connection_string).unwrap();
    let mut observer = observer(&database);
    let runtime = runtime();
    let state = LookupDigest::from_bytes([3; 32]);
    let browser = LookupDigest::from_bytes([4; 32]);
    runtime
        .block_on(store.create_login(login_attempt(state, browser)))
        .unwrap();
    observer
        .batch_execute(
            "CREATE FUNCTION stall_worker_take() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_sleep(20); RETURN OLD; END $$;
         CREATE TRIGGER stall_worker_take BEFORE DELETE ON apex_browser_login_attempts
         FOR EACH ROW EXECUTE FUNCTION stall_worker_take()",
        )
        .unwrap();
    let (abort, abort_requested) = oneshot::channel();
    std::thread::scope(|scope| {
        let caller = scope.spawn(move || {
            runtime.block_on(async move {
                // This is the only facade owner, including inside the child.
                let task = tokio::spawn(async move { store.take_login(state, browser).await });
                abort_requested.await.unwrap();
                task.abort();
                let Err(error) = task.await else {
                    panic!("stalled caller must be cancelled")
                };
                assert!(error.is_cancelled());
                tokio::time::sleep(Duration::from_millis(20)).await;
            });
        });
        // Synchronous observer, signaling and join all remain outside Tokio.
        wait_for_pg_sleep(&mut observer, &application_name);
        let cancelled_at = Instant::now();
        abort.send(()).unwrap();
        caller.join().unwrap();
        assert!(
            cancelled_at.elapsed() < Duration::from_millis(500),
            "cancellation must not join the stalled PG owner"
        );
    });
    // The existing store transport bounds the active command at five seconds.
    wait_closed(&mut observer, &application_name);
    let remaining: i64 = observer
        .query_one("SELECT count(*) FROM apex_browser_login_attempts", &[])
        .unwrap()
        .get(0);
    assert_eq!(remaining, 1, "the interrupted DELETE must not be replayed");
}
