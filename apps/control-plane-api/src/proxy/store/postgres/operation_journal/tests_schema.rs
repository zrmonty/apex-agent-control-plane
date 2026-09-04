use super::*;

const JOURNAL_SCHEMA: &str =
    include_str!("../../../../../../../deploy/postgres/mcp_proxy_operations.sql");

fn base_schema(tx: &mut Transaction<'_>) {
    let schema = format!("journal_version_test_{}", Uuid::now_v7().simple());
    tx.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();
    tx.query_one("SELECT set_config('search_path', $1, true)", &[&schema])
        .unwrap();
    tx.batch_execute(include_str!(
        "../../../../../../../deploy/postgres/mcp_proxies.sql"
    ))
    .unwrap();
}

fn catalog(tx: &mut Transaction<'_>) -> Vec<String> {
    tx.query(
        "SELECT definition FROM (
            SELECT 'relation:' || c.relname || ':' || c.relkind::text AS definition
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema()
            UNION ALL
            SELECT 'column:' || c.relname || ':' || a.attname || ':' ||
                format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text
            FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema() AND a.attnum > 0 AND NOT a.attisdropped
            UNION ALL
            SELECT 'constraint:' || c.conname || ':' || pg_get_constraintdef(c.oid)
            FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE n.nspname = current_schema()
            UNION ALL
            SELECT 'function:' || pg_get_functiondef(p.oid)
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = current_schema()
            UNION ALL
            SELECT 'trigger:' || pg_get_triggerdef(t.oid)
            FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema() AND NOT t.tgisinternal
        ) objects ORDER BY definition",
        &[],
    )
    .unwrap()
    .into_iter()
    .map(|row| row.get(0))
    .collect()
}

fn versions(tx: &mut Transaction<'_>) -> Vec<i32> {
    tx.query(
        "SELECT version FROM mcp_proxy_operation_schema ORDER BY version",
        &[],
    )
    .unwrap()
    .into_iter()
    .map(|row| row.get(0))
    .collect()
}

fn rejected_migration_preserves_schema(tx: &mut Transaction<'_>) {
    let before = catalog(tx);
    let marker_exists = tx
        .query_one(
            "SELECT to_regclass('mcp_proxy_operation_schema') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get::<_, bool>(0);
    let before_versions = marker_exists.then(|| versions(tx));
    let mut migration = tx.transaction().unwrap();
    let result = migration.batch_execute(JOURNAL_SCHEMA);
    if result.is_err() {
        migration.rollback().unwrap();
    } else {
        migration.commit().unwrap();
    }
    let error = result.expect_err("unsupported or inconsistent journal version must be refused");
    assert_eq!(
        error.code(),
        Some(&postgres::error::SqlState::FEATURE_NOT_SUPPORTED),
        "the version gate must reject before attempting journal DDL"
    );
    assert_eq!(
        catalog(tx),
        before,
        "rejection must preserve all existing DDL and functions"
    );
    if let Some(before_versions) = before_versions {
        assert_eq!(
            versions(tx),
            before_versions,
            "rejection must not insert version 1"
        );
    }
}

#[test]
fn schema_accepts_fresh_and_repeated_current_version_one() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let revision = fixture(&mut tx);
    assert_eq!(versions(&mut tx), vec![1]);
    let scope = scope();
    let proxy = proxy();
    let target = Target {
        scope: &scope,
        proxy_id: &proxy,
    };
    let event = envelope();
    let accepted = submit_operation(&mut tx, &submission(target, &revision, &event)).unwrap();
    let before = catalog(&mut tx);
    let intents = pending_evidence_intents(&mut tx, target, 10).unwrap();
    for _ in 0..2 {
        tx.batch_execute(JOURNAL_SCHEMA).unwrap();
        assert_eq!(versions(&mut tx), vec![1]);
        assert_eq!(catalog(&mut tx), before);
        assert_eq!(
            get_operation(&mut tx, target, &accepted.operation_id).unwrap(),
            Some(accepted.clone())
        );
        assert_eq!(
            pending_evidence_intents(&mut tx, target, 10).unwrap(),
            intents
        );
    }
}

#[test]
fn schema_rejects_version_two_without_creating_tables_or_replacing_functions() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    base_schema(&mut tx);
    tx.batch_execute(
        "CREATE TABLE mcp_proxy_operation_schema (version INTEGER PRIMARY KEY);
         INSERT INTO mcp_proxy_operation_schema VALUES (2);
         CREATE FUNCTION mcp_proxy_preserve_operation() RETURNS trigger
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'version two sentinel'; END; $$;",
    )
    .unwrap();
    rejected_migration_preserves_schema(&mut tx);
}

#[test]
fn schema_rejects_version_two_before_touching_incompatible_journal_ddl() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    base_schema(&mut tx);
    tx.batch_execute(
        "CREATE TABLE mcp_proxy_operation_schema (version INTEGER PRIMARY KEY);
         INSERT INTO mcp_proxy_operation_schema VALUES (2);
         CREATE TABLE mcp_proxy_operations (future_layout TEXT NOT NULL);
         INSERT INTO mcp_proxy_operations VALUES ('preserve version two data');",
    )
    .unwrap();
    rejected_migration_preserves_schema(&mut tx);
    assert_eq!(
        tx.query_one("SELECT future_layout FROM mcp_proxy_operations", &[])
            .unwrap()
            .get::<_, String>(0),
        "preserve version two data"
    );
}

#[test]
fn schema_rejects_mixed_versions_without_mutation() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    base_schema(&mut tx);
    tx.batch_execute(
        "CREATE TABLE mcp_proxy_operation_schema (version INTEGER PRIMARY KEY);
         INSERT INTO mcp_proxy_operation_schema VALUES (1), (2);",
    )
    .unwrap();
    rejected_migration_preserves_schema(&mut tx);
}

#[test]
fn schema_rejects_empty_existing_version_marker_without_mutation() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    base_schema(&mut tx);
    tx.batch_execute("CREATE TABLE mcp_proxy_operation_schema (version INTEGER PRIMARY KEY)")
        .unwrap();
    rejected_migration_preserves_schema(&mut tx);
}

#[test]
fn schema_rejects_unversioned_existing_journal_without_mutation() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    fixture(&mut tx);
    tx.batch_execute("DROP TABLE mcp_proxy_operation_schema")
        .unwrap();
    rejected_migration_preserves_schema(&mut tx);
}

#[test]
fn schema_rejects_version_one_with_missing_journal_tables_without_mutation() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    base_schema(&mut tx);
    tx.batch_execute(
        "CREATE TABLE mcp_proxy_operation_schema (version INTEGER PRIMARY KEY);
         INSERT INTO mcp_proxy_operation_schema VALUES (1);",
    )
    .unwrap();
    rejected_migration_preserves_schema(&mut tx);
}
