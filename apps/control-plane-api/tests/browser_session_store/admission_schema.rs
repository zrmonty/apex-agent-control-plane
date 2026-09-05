//! Format-2 preparation controls. Envelope and payload formats remain version 1.
use super::{regression_support::*, *};

fn snapshot(client: &mut Client) -> ((String, String), Vec<String>) {
    let mut data = Vec::new();
    for table in [
        "apex_browser_sessions",
        "apex_browser_login_attempts",
        "apex_browser_login_admission",
    ] {
        let present: bool = client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
            .unwrap()
            .get(0);
        data.push(if present {
            client.query_one(&format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM {table} r"
            ), &[]).unwrap().get(0)
        } else { "absent".into() });
    }
    (schema_drift::catalog(client), data)
}

fn populated(db: &Database) {
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    store.create_session(session(digest(121), 300)).unwrap();
    store
        .create_login(login(digest(122), digest(123), now() + 300))
        .unwrap();
}

fn assert_refused_unchanged(db: &Database, client: &mut Client) {
    let before = snapshot(client);
    assert!(
        PostgresSessionStore::connect(&db.url).is_err(),
        "incompatible storage was accepted"
    );
    assert!(
        snapshot(client) == before,
        "refusal mutated catalog or protected data"
    );
}

#[test]
fn fresh_v2_has_one_bounded_admission_row_and_v1_envelopes() {
    let db = Database::new();
    populated(&db);
    let mut client = db.client();
    let version: i32 = client
        .query_one("SELECT version FROM apex_browser_session_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(version, 2);
    let rows = client
        .query(
            "SELECT singleton,tat_us,clock_us FROM apex_browser_login_admission",
            &[],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i16>(0), 1);
    assert_eq!(rows[0].get::<_, i64>(1), 0);
    assert_eq!(rows[0].get::<_, i64>(2), 0);
    for table in ["apex_browser_sessions", "apex_browser_login_attempts"] {
        let version: i32 = client
            .query_one(&format!("SELECT token_version FROM {table}"), &[])
            .unwrap()
            .get(0);
        assert_eq!(
            version, 1,
            "metadata version must not change envelope semantics"
        );
    }
    assert!(
        client
            .execute(
                "INSERT INTO apex_browser_login_admission VALUES(2,0,0)",
                &[]
            )
            .is_err()
    );
    assert!(
        client
            .execute(
                "INSERT INTO apex_browser_login_admission VALUES(1,0,0)",
                &[]
            )
            .is_err()
    );
}

#[test]
fn compatible_v2_reopen_preserves_data_and_admission_debt() {
    let db = Database::new();
    populated(&db);
    let mut client = db.client();
    client.execute("UPDATE apex_browser_login_admission SET tat_us=1800000060000000,clock_us=1800000000000000", &[]).unwrap();
    let before = snapshot(&mut client);
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    assert!(store.load(digest(121)).unwrap().is_some());
    assert!(
        snapshot(&mut client) == before,
        "reopen must not reset debt or rewrite encrypted records"
    );
}

#[test]
fn exact_legacy_v1_is_refused_without_migration_or_data_loss() {
    let db = Database::new();
    populated(&db);
    let mut client = db.client();
    // Restore precisely the old three-table metadata format in this UUID schema.
    client.batch_execute(
        "DROP TABLE apex_browser_login_admission;
         ALTER TABLE apex_browser_session_schema DROP CONSTRAINT apex_browser_session_schema_version_check;
         UPDATE apex_browser_session_schema SET version=1;
         ALTER TABLE apex_browser_session_schema ADD CONSTRAINT apex_browser_session_schema_version_check CHECK(version=1)"
    ).unwrap();
    assert_refused_unchanged(&db, &mut client);
}

#[test]
fn orphan_admission_table_prevents_fresh_schema_creation() {
    let db = Database::new();
    let mut client = db.client();
    client
        .batch_execute(
            "CREATE TABLE apex_browser_login_admission (
            singleton smallint PRIMARY KEY CHECK(singleton=1),
            tat_us bigint NOT NULL CHECK(tat_us>=0),
            clock_us bigint NOT NULL CHECK(clock_us>=0));
         INSERT INTO apex_browser_login_admission VALUES(1,0,0)",
        )
        .unwrap();
    assert_refused_unchanged(&db, &mut client);
}

#[test]
fn missing_v2_admission_table_is_not_repaired() {
    let db = Database::new();
    populated(&db);
    let mut client = db.client();
    client
        .batch_execute("DROP TABLE apex_browser_login_admission")
        .unwrap();
    assert_refused_unchanged(&db, &mut client);
}

#[test]
fn missing_v2_singleton_is_not_refilled_on_startup() {
    let db = Database::new();
    populated(&db);
    let mut client = db.client();
    client
        .execute("DELETE FROM apex_browser_login_admission", &[])
        .unwrap();
    assert_refused_unchanged(&db, &mut client);
}

#[test]
fn admission_catalog_drift_is_refused_without_repair() {
    for change in [
        "ALTER TABLE apex_browser_login_admission SET UNLOGGED",
        "ALTER TABLE apex_browser_login_admission ALTER COLUMN tat_us DROP NOT NULL",
        "ALTER TABLE apex_browser_login_admission ALTER COLUMN singleton TYPE integer",
        "ALTER TABLE apex_browser_login_admission ALTER COLUMN clock_us SET DEFAULT 0",
        "ALTER TABLE apex_browser_login_admission ADD COLUMN extra integer",
        "ALTER TABLE apex_browser_login_admission ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE apex_browser_login_admission DROP CONSTRAINT apex_browser_login_admission_pkey",
        "ALTER TABLE apex_browser_login_admission DROP CONSTRAINT apex_browser_login_admission_singleton_check",
        "ALTER TABLE apex_browser_login_admission DROP CONSTRAINT apex_browser_login_admission_tat_us_check;
         ALTER TABLE apex_browser_login_admission ADD CHECK(tat_us>=0) NOT VALID",
    ] {
        let db = Database::new();
        populated(&db);
        let mut client = db.client();
        client.batch_execute(change).unwrap();
        assert_refused_unchanged(&db, &mut client);
    }
}

#[test]
fn reconnect_cannot_recreate_a_deleted_admission_singleton() {
    let db = Database::new();
    let worker = StoreWorker::new(&db, false);
    let mut client = observer(&db);
    client
        .execute("DELETE FROM apex_browser_login_admission", &[])
        .unwrap();
    let before = snapshot(&mut client);
    terminate(&worker, &mut client);
    assert!(worker.run(|store| store.admit_login()).is_err());
    assert!(snapshot(&mut client) == before);
}
