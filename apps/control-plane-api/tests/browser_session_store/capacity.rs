use super::{regression_support::*, *};

const CAPACITY_LOCK: i64 = 0x0A9E_1DE3_0000_0051;

#[derive(Clone, Copy)]
enum Kind {
    Login,
    Session,
}

fn table(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "apex_browser_login_attempts",
        Kind::Session => "apex_browser_sessions",
    }
}

fn prefill(db: &Database, kind: Kind) -> i64 {
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    let key = digest(70);
    let mut client = observer(db);
    match kind {
        Kind::Login => {
            let expiry = db_now(&mut client) + 300;
            store.create_login(login(key, digest(71), expiry)).unwrap();
            client.execute(
                "INSERT INTO apex_browser_login_attempts
                 (state_digest,browser_digest,issuer,client_id,created_at,expires_at,
                  token_version,token_key_id,token_nonce,token_ciphertext)
                 SELECT decode(lpad(to_hex(n),64,'0'),'hex'),browser_digest,issuer,client_id,
                        created_at,expires_at,token_version,token_key_id,token_nonce,token_ciphertext
                 FROM apex_browser_login_attempts CROSS JOIN generate_series(1,998) n
                 WHERE state_digest=$1",
                &[&key.as_bytes().as_slice()],
            ).unwrap();
            1000
        }
        Kind::Session => {
            store.create_session(session(key, 300)).unwrap();
            client.execute(
                "INSERT INTO apex_browser_sessions
                 (session_digest,issuer,client_id,subject,csrf_binding,created_at,
                  absolute_expires_at,idle_expires_at,access_expires_at,refresh_expires_at,
                  generation,state,refresh_deadline,token_version,token_key_id,token_nonce,token_ciphertext)
                 SELECT decode(lpad(to_hex(n),64,'0'),'hex'),issuer,client_id,subject,csrf_binding,
                        created_at,absolute_expires_at,idle_expires_at,access_expires_at,refresh_expires_at,
                        generation,state,refresh_deadline,token_version,token_key_id,token_nonce,token_ciphertext
                 FROM apex_browser_sessions CROSS JOIN generate_series(1,9998) n
                 WHERE session_digest=$1",
                &[&key.as_bytes().as_slice()],
            ).unwrap();
            10000
        }
    }
}

fn serialized_capacity(kind: Kind, repeatable_read: bool, reconnect: bool) {
    let db = Database::new();
    let cap = prefill(&db, kind);
    let first = StoreWorker::new(&db, repeatable_read);
    let second = StoreWorker::new(&db, repeatable_read);
    let mut observer = observer(&db);
    if reconnect {
        for worker in [&first, &second] {
            terminate(worker, &mut observer);
            let loaded = worker.run(|store| store.load(digest(240)));
            if loaded.is_err() {
                diagnose_reconnect(&db, &worker.application);
            }
            assert!(loaded.unwrap().is_none());
        }
    }
    let before: i64 = observer
        .query_one(&format!("SELECT count(*) FROM {}", table(kind)), &[])
        .unwrap()
        .get(0);
    assert_eq!(before, cap - 1);
    let expiry = db_now(&mut observer) + 300;
    let mut blocker = db.client();
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    blocker
        .query_one("SELECT pg_advisory_lock($1)", &[&CAPACITY_LOCK])
        .unwrap();
    // Both operations must enter their capacity transactions before releasing
    // the lock. Under inherited Repeatable Read both used to retain cap-1.
    let results: Vec<_> = [&first, &second]
        .into_iter()
        .enumerate()
        .map(|(i, worker)| {
            let key = if i == 0 { digest(72) } else { digest(73) };
            worker.submit(move |store| match kind {
                Kind::Login => store.create_login(login(key, digest(74), expiry)),
                Kind::Session => store.create_session(session(key, 300)),
            })
        })
        .collect();
    for worker in [&first, &second] {
        wait_for_blocker(&mut observer, &worker.application, blocker_pid);
    }
    let unlocked: bool = blocker
        .query_one("SELECT pg_advisory_unlock($1)", &[&CAPACITY_LOCK])
        .unwrap()
        .get(0);
    assert!(unlocked);
    let outcomes: Vec<_> = results.into_iter().map(receive).collect();
    let after: i64 = observer
        .query_one(&format!("SELECT count(*) FROM {}", table(kind)), &[])
        .unwrap()
        .get(0);
    assert_eq!(
        after, cap,
        "serialized creators must not exceed durable capacity"
    );
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
}

// Failure-only diagnostic; never retries a store operation or changes its
// assertion. A separate owned-fixture connection checks the exact reconnect SQL
// and reports only fixed stages, SQLSTATE, and session counts (no SQL/row data).
fn diagnose_reconnect(db: &Database, application: &str) {
    let mut client = observer(db);
    let connections: i64 = client.query_one(
        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1",
        &[&application],
    ).unwrap().get(0);
    eprintln!("reconnect diagnostic: named_store_connections={connections}");
    let mut stage = "begin";
    let probe = (|| -> Result<(), postgres::Error> {
        let mut tx = client.transaction()?;
        stage = "isolation";
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")?;
        stage = "schema_lock";
        tx.query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&0x0A9E_1DE3_0000_0050_i64],
        )?;
        stage = "validation_mode";
        tx.query_one(
            "SELECT set_config('apex.browser_session_create','off',true)",
            &[],
        )?;
        stage = "catalog_validation";
        tx.batch_execute(include_str!(
            "../../../../deploy/postgres/operator_sessions.sql"
        ))?;
        stage = "commit";
        tx.commit()
    })();
    match probe {
        Ok(()) => eprintln!("reconnect diagnostic: independent validation-only SQL passed"),
        Err(error) => eprintln!(
            "reconnect diagnostic: stage={stage} sqlstate={:?}",
            error.code().map(postgres::error::SqlState::code),
        ),
    }
}

#[test]
fn login_capacity_rejects_stale_repeatable_read_snapshot() {
    serialized_capacity(Kind::Login, true, false);
}
#[test]
fn session_capacity_rejects_stale_repeatable_read_snapshot() {
    serialized_capacity(Kind::Session, true, false);
}
#[test]
fn login_capacity_remains_bounded_after_repeatable_read_reconnect() {
    serialized_capacity(Kind::Login, true, true);
}
#[test]
fn session_capacity_remains_bounded_after_repeatable_read_reconnect() {
    serialized_capacity(Kind::Session, true, true);
}
#[test]
fn login_capacity_serializes_default_isolation_creators() {
    serialized_capacity(Kind::Login, false, false);
}
#[test]
fn session_capacity_serializes_default_isolation_creators() {
    serialized_capacity(Kind::Session, false, false);
}
