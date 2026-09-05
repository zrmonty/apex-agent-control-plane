use super::support::*;
use apex_durability::{
    PostgresClientError as WorkerPostgresError, PostgresClientOps, PostgresConnection,
    connect_postgres_for_worker,
};
use std::time::{Duration, Instant};

const TEST_LIMIT: Duration = Duration::from_secs(7);

fn connection(fixture: &Database) -> PostgresConnection {
    connect_postgres_for_worker(&fixture.url).expect("dedicated PostgreSQL unavailable")
}

#[test]
fn query_deadline_closes_client_until_explicit_reconnect() {
    let fixture = Database::new();
    let mut client = connection(&fixture);
    let original_pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    // Force the client deadline to win instead of the independent server timeout.
    client.batch_execute("SET statement_timeout = 0").unwrap();
    let start = Instant::now();
    let error = client.query("SELECT pg_sleep(10)", &[]).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Deadline), "{error:?}");
    assert!(start.elapsed() < TEST_LIMIT);
    assert!(client.is_closed());
    let start = Instant::now();
    assert!(matches!(
        client.query_one("SELECT 1", &[]),
        Err(WorkerPostgresError::Closed)
    ));
    drop(client);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "closed client must not retry or block drop"
    );
    let mut replacement = connection(&fixture);
    assert!(!replacement.is_closed());
    let row = replacement
        .query_one("SELECT pg_backend_pid(), 42::int", &[])
        .unwrap();
    assert_ne!(row.get::<_, i32>(0), original_pid);
    assert_eq!(row.get::<_, i32>(1), 42);
}

#[test]
fn execute_and_batch_deadlines_close_the_connection() {
    for batch in [false, true] {
        let fixture = Database::new();
        let mut client = connection(&fixture);
        client.batch_execute("SET statement_timeout = 0").unwrap();
        let start = Instant::now();
        let result = if batch {
            client.batch_execute("SELECT pg_sleep(10)")
        } else {
            client.execute("SELECT pg_sleep(10)", &[]).map(|_| ())
        };
        assert!(matches!(result, Err(WorkerPostgresError::Deadline)));
        assert!(start.elapsed() < TEST_LIMIT);
        assert!(client.is_closed());
    }
}

#[test]
fn startup_deadlines_preserve_configured_search_path() {
    let fixture = Database::new();
    let expected: String = fixture
        .client()
        .query_one("SELECT current_setting('search_path')", &[])
        .unwrap()
        .get(0);
    let mut client = connection(&fixture);
    let row = client
        .query_one(
            "SELECT current_setting('search_path'), current_setting('statement_timeout'),
         current_setting('lock_timeout')",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), expected);
    assert_eq!(row.get::<_, String>(1), "5s");
    assert_eq!(row.get::<_, String>(2), "2s");
}

#[test]
fn nested_transactions_commit_rollback_and_drop_at_their_own_savepoints() {
    let fixture = Database::new();
    let mut client = connection(&fixture);
    client
        .batch_execute("CREATE TEMP TABLE worker_values (value INTEGER PRIMARY KEY)")
        .unwrap();
    let mut outer = client.transaction().unwrap();
    assert_eq!(
        outer
            .execute("INSERT INTO worker_values VALUES ($1)", &[&1_i32])
            .unwrap(),
        1
    );
    {
        let mut child = outer.transaction().unwrap();
        child
            .batch_execute("INSERT INTO worker_values VALUES (2)")
            .unwrap();
        let mut grandchild = child.transaction().unwrap();
        grandchild
            .execute("INSERT INTO worker_values VALUES (3)", &[])
            .unwrap();
        grandchild.commit().unwrap();
        assert_eq!(
            child
                .query_one("SELECT count(*) FROM worker_values", &[])
                .unwrap()
                .get::<_, i64>(0),
            3
        );
        child.rollback().unwrap();
    }
    {
        let mut dropped = outer.transaction().unwrap();
        dropped
            .execute("INSERT INTO worker_values VALUES (4)", &[])
            .unwrap();
        assert!(
            dropped
                .query_opt("SELECT value FROM worker_values WHERE value = 99", &[])
                .unwrap()
                .is_none()
        );
    }
    {
        let mut committed = outer.transaction().unwrap();
        committed
            .execute("INSERT INTO worker_values VALUES (5)", &[])
            .unwrap();
        committed.commit().unwrap();
    }
    let values: Vec<i32> = outer
        .query("SELECT value FROM worker_values ORDER BY value", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(values, vec![1, 5]);
    outer.commit().unwrap();
    let values: Vec<i32> = client
        .query("SELECT value FROM worker_values ORDER BY value", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(values, vec![1, 5]);
    let mut rolled_back = client.transaction().unwrap();
    rolled_back
        .execute("INSERT INTO worker_values VALUES (6)", &[])
        .unwrap();
    rolled_back.rollback().unwrap();
    {
        let mut dropped = client.transaction().unwrap();
        dropped
            .execute("INSERT INTO worker_values VALUES (7)", &[])
            .unwrap();
    }
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM worker_values", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
}

#[test]
fn database_errors_preserve_sqlstate_and_savepoint_rollback_restores_parent() {
    let fixture = Database::new();
    let mut client = connection(&fixture);
    client
        .batch_execute("CREATE TEMP TABLE worker_unique (value INTEGER PRIMARY KEY)")
        .unwrap();
    let mut outer = client.transaction().unwrap();
    outer
        .execute("INSERT INTO worker_unique VALUES (1)", &[])
        .unwrap();
    {
        let mut nested = outer.transaction().unwrap();
        let error = nested
            .execute("INSERT INTO worker_unique VALUES (1)", &[])
            .unwrap_err();
        assert!(matches!(error, WorkerPostgresError::Database(_)));
        assert_eq!(
            error.code(),
            Some(&postgres::error::SqlState::UNIQUE_VIOLATION)
        );
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(
        outer
            .query_one("SELECT count(*) FROM worker_unique", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    outer.commit().unwrap();
    assert!(!client.is_closed());
}

#[test]
fn transaction_query_deadline_makes_nested_drop_and_parent_drop_nonblocking() {
    let fixture = Database::new();
    let mut client = connection(&fixture);
    client.batch_execute("SET statement_timeout = 0").unwrap();
    let mut outer = client.transaction().unwrap();
    let mut nested = outer.transaction().unwrap();
    let start = Instant::now();
    let error = nested.query_opt("SELECT pg_sleep(10)", &[]).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Deadline));
    assert!(start.elapsed() < TEST_LIMIT);
    let start = Instant::now();
    drop(nested);
    drop(outer);
    assert!(client.is_closed());
    drop(client);
    assert!(start.elapsed() < Duration::from_secs(1));
}
