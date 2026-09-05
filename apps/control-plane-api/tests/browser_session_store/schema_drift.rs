use super::{regression_support::*, *};

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

// Observe catalog structure, defaults, validated checks, index keys/predicates,
// persistence, and marker rows. Failed validation must leave all of it unchanged.
pub(super) fn catalog(client: &mut Client) -> (String, String) {
    let shape: String = client.query_one(
        "SELECT jsonb_build_object(
          'relations', (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.name) FROM (
            SELECT c.relname AS name,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=current_schema()) r),
          'columns', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.table_name,a.attnum) FROM (
            SELECT c.relname AS table_name,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,
                   a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid) AS default_value
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE n.nspname=current_schema() AND a.attnum>0 AND NOT a.attisdropped) a),
          'constraints', (SELECT jsonb_agg(to_jsonb(k) ORDER BY k.table_name,k.conname) FROM (
            SELECT c.relname AS table_name,k.conname,k.contype,k.conkey,k.convalidated,
                   k.condeferrable,k.condeferred,pg_get_constraintdef(k.oid) AS definition
            FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=current_schema()) k),
          'indexes', (SELECT jsonb_agg(to_jsonb(i) ORDER BY i.name) FROM (
            SELECT c.relname AS name,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,
                   pg_get_indexdef(i.indexrelid) AS definition
            FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=current_schema()) i),
          'functions', (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.name,p.identity_args) FROM (
            SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS identity_args,
                   p.prosrc,p.provolatile,p.prosecdef
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=current_schema()) p)
         )::text", &[],
    ).unwrap().get(0);
    let exists: bool = client
        .query_one(
            "SELECT to_regclass('apex_browser_session_schema') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    let marker = if exists {
        client.query_one(
            "SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb)::text
             FROM apex_browser_session_schema m", &[],
        ).unwrap().get(0)
    } else {
        "absent".to_owned()
    };
    (shape, marker)
}

fn rejected_without_ddl(change: impl FnOnce(&mut Client)) {
    let db = Database::new();
    drop(PostgresSessionStore::connect(&db.url).unwrap());
    let mut client = observer(&db);
    change(&mut client);
    let before = catalog(&mut client);
    let rejected = PostgresSessionStore::connect(&db.url).is_err();
    let after = catalog(&mut client);
    assert!(
        before == after,
        "schema refusal changed the catalog or marker rows"
    );
    assert!(rejected, "incompatible current-format storage was accepted");
}

fn drop_primary(client: &mut Client, table: &str) {
    let constraint: String = client
        .query_one(
            "SELECT conname FROM pg_constraint WHERE conrelid=$1::text::regclass AND contype='p'",
            &[&table],
        )
        .unwrap()
        .get(0);
    client
        .batch_execute(&format!(
            "ALTER TABLE {} DROP CONSTRAINT {}",
            quoted(table),
            quoted(&constraint),
        ))
        .unwrap();
}

enum CheckChange {
    Missing,
    NotValidated,
    Weakened,
}

fn alter_check(client: &mut Client, table: &str, pattern: &str, change: CheckChange) {
    let row = client
        .query_one(
            "SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
         WHERE conrelid=$1::text::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE $2",
            &[&table, &pattern],
        )
        .unwrap();
    let name: String = row.get("conname");
    let definition: String = row.get("definition");
    client
        .batch_execute(&format!(
            "ALTER TABLE {} DROP CONSTRAINT {}",
            quoted(table),
            quoted(&name),
        ))
        .unwrap();
    match change {
        CheckChange::Missing => {}
        CheckChange::NotValidated => {
            client
                .batch_execute(&format!(
                    "ALTER TABLE {} ADD CONSTRAINT {} {definition} NOT VALID",
                    quoted(table),
                    quoted(&name),
                ))
                .unwrap();
        }
        CheckChange::Weakened => {
            client
                .batch_execute(&format!(
                    "ALTER TABLE {} ADD CONSTRAINT {} CHECK (token_version>0)",
                    quoted(table),
                    quoted(&name),
                ))
                .unwrap();
        }
    }
}

macro_rules! drift_case {
    ($name:ident, $sql:literal) => {
        #[test]
        fn $name() {
            rejected_without_ddl(|client| client.batch_execute($sql).unwrap());
        }
    };
}

#[test]
fn schema_rejects_marker_primary_key_drift_without_adding_marker_rows() {
    rejected_without_ddl(|client| {
        drop_primary(client, "apex_browser_session_schema");
        client
            .batch_execute(
                "ALTER TABLE apex_browser_session_schema ALTER COLUMN version SET NOT NULL",
            )
            .unwrap();
    });
}
#[test]
fn schema_rejects_session_primary_key_drift() {
    rejected_without_ddl(|client| drop_primary(client, "apex_browser_sessions"));
}
#[test]
fn schema_rejects_login_primary_key_drift() {
    rejected_without_ddl(|client| drop_primary(client, "apex_browser_login_attempts"));
}

drift_case!(
    schema_rejects_missing_session_column,
    "ALTER TABLE apex_browser_sessions DROP COLUMN csrf_binding"
);
drift_case!(
    schema_rejects_missing_login_column,
    "ALTER TABLE apex_browser_login_attempts DROP COLUMN issuer"
);
drift_case!(
    schema_rejects_wrong_session_column_type,
    "ALTER TABLE apex_browser_sessions ALTER COLUMN generation TYPE integer USING generation::integer"
);
drift_case!(
    schema_rejects_nullable_csrf_column,
    "ALTER TABLE apex_browser_sessions ALTER COLUMN csrf_binding DROP NOT NULL"
);
drift_case!(
    schema_rejects_changed_generation_default,
    "ALTER TABLE apex_browser_sessions ALTER COLUMN generation SET DEFAULT 7"
);
drift_case!(
    schema_rejects_missing_generation_default,
    "ALTER TABLE apex_browser_sessions ALTER COLUMN generation DROP DEFAULT"
);
drift_case!(
    schema_rejects_changed_state_default,
    "ALTER TABLE apex_browser_sessions ALTER COLUMN state SET DEFAULT 'revoked'"
);
drift_case!(
    schema_rejects_changed_database_clock_default,
    "ALTER TABLE apex_browser_login_attempts ALTER COLUMN created_at SET DEFAULT 1"
);
drift_case!(
    schema_rejects_unlogged_sessions,
    "ALTER TABLE apex_browser_sessions SET UNLOGGED"
);
drift_case!(
    schema_rejects_unlogged_login_attempts,
    "ALTER TABLE apex_browser_login_attempts SET UNLOGGED"
);
drift_case!(
    schema_rejects_unlogged_marker,
    "ALTER TABLE apex_browser_session_schema SET UNLOGGED"
);

#[test]
fn schema_rejects_missing_marker_version_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_session_schema",
            "%version = 2%",
            CheckChange::Missing,
        )
    });
}
#[test]
fn schema_rejects_missing_session_ciphertext_bound() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_sessions",
            "%octet_length(token_ciphertext)%",
            CheckChange::Missing,
        )
    });
}
#[test]
fn schema_rejects_not_validated_login_nonce_bound() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_login_attempts",
            "%octet_length(token_nonce)%",
            CheckChange::NotValidated,
        )
    });
}
#[test]
fn schema_rejects_weakened_envelope_version_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_sessions",
            "%token_version = 1%",
            CheckChange::Weakened,
        )
    });
}
#[test]
fn schema_rejects_missing_session_lifetime_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_sessions",
            "%86400%",
            CheckChange::Missing,
        )
    });
}
#[test]
fn schema_rejects_missing_login_lifetime_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_login_attempts",
            "%600%",
            CheckChange::Missing,
        )
    });
}
#[test]
fn schema_rejects_missing_refresh_state_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_sessions",
            "%refresh_deadline IS NOT NULL%",
            CheckChange::Missing,
        )
    });
}
#[test]
fn schema_rejects_missing_revoked_ciphertext_constraint() {
    rejected_without_ddl(|client| {
        alter_check(
            client,
            "apex_browser_sessions",
            "%token_ciphertext IS NULL%",
            CheckChange::Missing,
        )
    });
}

fn reconnect_rejects(change: impl FnOnce(&mut Client)) {
    let db = Database::new();
    let worker = StoreWorker::new(&db, false);
    let mut client = observer(&db);
    change(&mut client);
    let before = catalog(&mut client);
    terminate(&worker, &mut client);
    assert!(
        worker.run(|store| store.load(digest(240))).is_err(),
        "reconnect must validate storage before allowing even an empty lookup",
    );
    assert!(
        catalog(&mut client) == before,
        "reconnect changed incompatible storage"
    );
}

#[test]
fn reconnect_revalidates_session_primary_key_before_operation() {
    reconnect_rejects(|client| drop_primary(client, "apex_browser_sessions"));
}
#[test]
fn reconnect_revalidates_schema_version_before_operation() {
    reconnect_rejects(|client| {
        alter_check(
            client,
            "apex_browser_session_schema",
            "%version = 2%",
            CheckChange::Missing,
        );
        client
            .batch_execute("UPDATE apex_browser_session_schema SET version=3")
            .unwrap();
    });
}
#[test]
fn reconnect_does_not_silently_recreate_missing_storage() {
    reconnect_rejects(|client| {
        client.batch_execute(
            "DROP TABLE apex_browser_login_attempts,apex_browser_sessions,apex_browser_session_schema,apex_browser_login_admission",
        ).unwrap();
    });
}
#[test]
fn compatible_schema_reopen_is_idempotent_and_preserves_sessions() {
    let db = Database::new();
    let mut first = PostgresSessionStore::connect(&db.url).unwrap();
    first.create_session(session(digest(81), 300)).unwrap();
    let original = first.load(digest(81)).unwrap().unwrap();
    drop(first);
    let mut client = observer(&db);
    let before = catalog(&mut client);
    let mut second = PostgresSessionStore::connect(&db.url).unwrap();
    let loaded = second.load(digest(81)).unwrap().unwrap();
    assert_eq!(loaded.envelope.ciphertext(), original.envelope.ciphertext());
    assert_eq!(loaded.generation, 0);
    assert_eq!(
        loaded.identity.absolute_expires_at,
        original.identity.absolute_expires_at
    );
    assert!(catalog(&mut client) == before);
}
