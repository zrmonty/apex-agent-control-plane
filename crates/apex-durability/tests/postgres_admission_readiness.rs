#![cfg(all(feature = "postgres", feature = "test-support"))]
//! Only runs against an explicitly supplied, disposable PostgreSQL fixture.
//! Never uses APEX_POSTGRES_URL or an existing application's database.

use apex_durability::{
    EventOutbox, GatewayErrorCode, IdempotencyKey, IdempotencyReservation, IdempotencyStore,
    PostgresIdempotencyStore, PostgresOutbox, ReservationResult,
};
use postgres::{Client, Config, NoTls};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[path = "postgres_readiness_support/relay.rs"]
mod relay;

struct Fixture {
    admin: Client,
    url: String,
    role: String,
    database: String,
    root: Client,
}

impl Fixture {
    fn new() -> Option<Self> {
        if std::env::var("APEX_PG_READINESS_FIXTURE").ok().as_deref() != Some("1") {
            eprintln!("SKIP: set APEX_PG_READINESS_FIXTURE=1 and its isolated fixture URL");
            return None;
        }
        let url = std::env::var("APEX_PG_READINESS_FIXTURE_URL")
            .expect("explicit readiness fixture requires APEX_PG_READINESS_FIXTURE_URL");
        let config: Config = url.parse().expect("fixture configuration");
        assert_eq!(config.get_dbname(), Some("postgres"));
        assert_eq!(
            config.get_hosts(),
            &[postgres::config::Host::Tcp("127.0.0.1".into())]
        );
        assert_eq!(config.get_ssl_mode(), postgres::config::SslMode::Disable);
        let mut root = config
            .connect(NoTls)
            .expect("explicit fixture must be reachable");
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("readiness_{suffix}");
        let role = format!("reader_{suffix}");
        root.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'readiness_disposable_only';"
        ))
        .unwrap();
        root.batch_execute(&format!("CREATE DATABASE {database} OWNER {role}"))
            .unwrap();
        let mut admin_config = config.clone();
        admin_config.dbname(&database);
        let admin = admin_config.connect(NoTls).unwrap();
        let port = config.get_ports()[0];
        let url = format!(
            "host=127.0.0.1 port={port} user={role} password=readiness_disposable_only dbname={database} sslmode=disable"
        );
        Some(Self {
            admin,
            url,
            role,
            database,
            root,
        })
    }

    fn pair(&self, capacity: usize) -> (PostgresIdempotencyStore, PostgresOutbox) {
        (
            PostgresIdempotencyStore::connect_for_worker(&self.url, capacity).unwrap(),
            PostgresOutbox::connect_for_worker(&self.url, capacity).unwrap(),
        )
    }

    fn snapshot(&mut self) -> String {
        self.admin
            .query_one(
                "SELECT json_build_array(
              (SELECT json_agg(x ORDER BY event_id) FROM
                (SELECT t.*, xmin::text AS version FROM apex_ingest_idempotency t) x),
              (SELECT json_agg(x ORDER BY event_id) FROM
                (SELECT t.*, xmin::text AS version FROM apex_event_outbox t) x),
              (SELECT json_agg(x ORDER BY relname) FROM
                (SELECT relname, oid, relfilenode, relpersistence FROM pg_class
                 WHERE relnamespace = 'public'::regnamespace) x))::text",
                &[],
            )
            .unwrap()
            .get(0)
    }

    fn seed(&mut self, table: &str, count: i32, same_scope: bool) {
        let extra = if table == "apex_ingest_idempotency" {
            ", reservation_id"
        } else {
            ", envelope"
        };
        let value = if table == "apex_ingest_idempotency" {
            ", md5(('reservation' || n)::text)::uuid"
        } else {
            ", decode('01', 'hex')"
        };
        self.admin
            .execute(
                &format!(
            "INSERT INTO {table} (workspace_id, namespace_id, event_id, payload_hash, state{extra})
             SELECT CASE WHEN $2 THEN 'ws' ELSE 'ws' || n END, 'ns', md5(n::text)::uuid,
               decode(repeat('00', 32), 'hex'), 'pending'{value}
             FROM generate_series(1, $1::int) n"
        ),
                &[&count, &same_scope],
            )
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Generated identifiers only, in the explicitly opted-in disposable server.
        // DROP DATABASE cannot run in the implicit transaction of a multi-
        // statement query. Keep the two operations separate and surface errors.
        let result = self
            .root
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
            .and_then(|()| self.root.batch_execute(&format!("DROP ROLE {}", self.role)));
        if let Err(error) = result {
            eprintln!("owned readiness fixture cleanup failed: {error}");
            assert!(std::thread::panicking(), "fixture cleanup failed");
        }
    }
}

fn ready(pair: &mut (PostgresIdempotencyStore, PostgresOutbox)) {
    pair.0
        .check_admission_readiness("ws", "ns")
        .expect("idempotency ready");
    pair.1
        .check_admission_readiness("ws", "ns")
        .expect("outbox ready");
}

fn denied(pair: &mut (PostgresIdempotencyStore, PostgresOutbox)) {
    assert!(pair.0.check_admission_readiness("ws", "ns").is_err());
    assert!(pair.1.check_admission_readiness("ws", "ns").is_err());
}

#[test]
fn observations_preserve_rows_versions_catalog_and_reservation_handles() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    let key = |id: &str| IdempotencyKey {
        workspace_id: "ws".into(),
        namespace_id: "ns".into(),
        event_id: id.into(),
    };
    let first = match pair
        .0
        .reserve(key("01900000-0000-7000-8000-000000000001"), [1; 32])
        .unwrap()
    {
        ReservationResult::Reserved(handle) => handle,
        other => panic!("unexpected reservation: {other:?}"),
    };
    fixture.seed("apex_event_outbox", 3, true);
    fixture
        .admin
        .batch_execute(
            "UPDATE apex_event_outbox SET state='complete', completed_at=now()
      WHERE event_id=md5('1')::uuid;
      UPDATE apex_event_outbox SET quarantined_at=now(), quarantine_reason='fixture'
      WHERE event_id=md5('2')::uuid",
        )
        .unwrap();
    let before = fixture.snapshot();
    for _ in 0..3 {
        ready(&mut pair);
    }
    assert_eq!(
        fixture.snapshot(),
        before,
        "observation must not write or claim rows/DDL"
    );
    assert_eq!(first, IdempotencyReservation::from_token_for_test(1));
    let second = match pair
        .0
        .reserve(key("01900000-0000-7000-8000-000000000002"), [2; 32])
        .unwrap()
    {
        ReservationResult::Reserved(handle) => handle,
        other => panic!("unexpected reservation: {other:?}"),
    };
    assert_eq!(second, IdempotencyReservation::from_token_for_test(2));
    pair.0.commit(first).unwrap();
    pair.0.abort(second);
    let count: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM apex_ingest_idempotency WHERE state='committed'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "original handles remain usable after observations"
    );
}

#[test]
fn exact_capacity_includes_other_scopes_complete_and_quarantined_rows() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(80);
    ready(&mut pair);
    fixture.seed("apex_ingest_idempotency", 80, false);
    fixture.seed("apex_event_outbox", 80, false);
    fixture
        .admin
        .batch_execute(
            "UPDATE apex_event_outbox SET state='complete', completed_at=now()
      WHERE event_id=md5('1')::uuid;
      UPDATE apex_event_outbox SET quarantined_at=now(), quarantine_reason='fixture'
      WHERE event_id=md5('2')::uuid;
      SELECT pg_stat_reset()",
        )
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        pair.0
            .check_admission_readiness("ws", "ns")
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyCapacity
    );
    assert_eq!(
        pair.1
            .check_admission_readiness("ws", "ns")
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyCapacity
    );
    assert_eq!(fixture.snapshot(), before);
    fixture
        .admin
        .batch_execute(
            "DELETE FROM apex_ingest_idempotency WHERE event_id=md5('1')::uuid;
      DELETE FROM apex_event_outbox WHERE event_id=md5('1')::uuid",
        )
        .unwrap();
    ready(&mut pair);
}

#[test]
fn scoped_capacity_and_invalid_scopes_fail_without_mutation() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    fixture.seed("apex_ingest_idempotency", 4, true);
    fixture.admin.batch_execute("UPDATE apex_ingest_idempotency SET state='committed', committed_at=now() WHERE event_id=md5('1')::uuid").unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        pair.0
            .check_admission_readiness("ws", "ns")
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyCapacity
    );
    pair.0.check_admission_readiness("ws", "other").unwrap();
    pair.1.check_admission_readiness("ws", "ns").unwrap();
    for (ws, ns) in [("", "ns"), ("ws/x", "ns"), ("ws", "../ns")] {
        assert_eq!(
            pair.0.check_admission_readiness(ws, ns).unwrap_err().code,
            GatewayErrorCode::ScopeDenied
        );
        assert_eq!(
            pair.1.check_admission_readiness(ws, ns).unwrap_err().code,
            GatewayErrorCode::ScopeDenied
        );
    }
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn effective_role_privileges_and_rls_are_reobserved_on_owned_sessions() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    let role = fixture.role.clone();
    fixture
        .admin
        .batch_execute(&format!(
            "ALTER TABLE apex_ingest_idempotency OWNER TO postgres;
      ALTER TABLE apex_event_outbox OWNER TO postgres;
      GRANT SELECT, INSERT, UPDATE, DELETE ON apex_ingest_idempotency, apex_event_outbox TO {role}"
        ))
        .unwrap();
    ready(&mut pair);
    for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        fixture
            .admin
            .batch_execute(&format!(
                "REVOKE {privilege} ON apex_ingest_idempotency, apex_event_outbox FROM {role}"
            ))
            .unwrap();
        let before = fixture.snapshot();
        denied(&mut pair);
        assert_eq!(fixture.snapshot(), before);
        fixture
            .admin
            .batch_execute(&format!(
                "GRANT {privilege} ON apex_ingest_idempotency, apex_event_outbox TO {role}"
            ))
            .unwrap();
        ready(&mut pair);
    }
    fixture
        .admin
        .batch_execute(&format!(
            "ALTER SCHEMA public OWNER TO postgres;
         REVOKE USAGE ON SCHEMA public FROM PUBLIC, {role}"
        ))
        .unwrap();
    denied(&mut pair);
    fixture
        .admin
        .batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .unwrap();
    ready(&mut pair);
    fixture.seed("apex_ingest_idempotency", 64, false);
    fixture.seed("apex_event_outbox", 64, false);
    fixture
        .admin
        .batch_execute(
            "ALTER TABLE apex_ingest_idempotency ENABLE ROW LEVEL SECURITY;
      ALTER TABLE apex_event_outbox ENABLE ROW LEVEL SECURITY",
        )
        .unwrap();
    let before = fixture.snapshot();
    denied(&mut pair); // No policies: the real session sees zero rows, not global capacity.
    assert_eq!(fixture.snapshot(), before);
    // Reject active RLS before evaluating policies: SQL SELECT alone does not
    // prevent a volatile policy from writing evidence on an otherwise hidden row.
    fixture
        .admin
        .batch_execute(&format!(
            "CREATE TABLE observation_writes (marker int);
         GRANT INSERT ON observation_writes TO {role};
         CREATE FUNCTION observation_policy() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
         BEGIN INSERT INTO observation_writes VALUES (1); RETURN false; END $$;
         CREATE POLICY observation_policy ON apex_ingest_idempotency USING (observation_policy());
         CREATE POLICY observation_policy ON apex_event_outbox USING (observation_policy())"
        ))
        .unwrap();
    denied(&mut pair);
    let writes: i64 = fixture
        .admin
        .query_one("SELECT count(*) FROM observation_writes", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        writes, 0,
        "unusable relations must not evaluate row policies"
    );
}

#[test]
fn readonly_and_nonpersistent_relations_are_unavailable() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    fixture
        .admin
        .batch_execute(
            "ALTER TABLE apex_ingest_idempotency SET UNLOGGED;
      ALTER TABLE apex_event_outbox SET UNLOGGED",
        )
        .unwrap();
    let before = fixture.snapshot();
    denied(&mut pair);
    assert_eq!(fixture.snapshot(), before);
    fixture
        .admin
        .batch_execute(
            "ALTER TABLE apex_ingest_idempotency SET LOGGED;
      ALTER TABLE apex_event_outbox SET LOGGED",
        )
        .unwrap();
    ready(&mut pair);
    // Constructors retain their DDL. A fixture-only event trigger changes the
    // actual owning sessions to read-only after that startup transaction.
    fixture
        .admin
        .batch_execute(
            "CREATE FUNCTION readiness_readonly() RETURNS event_trigger LANGUAGE plpgsql AS $$
          BEGIN PERFORM set_config('default_transaction_read_only','on',false); END $$;
         CREATE EVENT TRIGGER readiness_readonly ON ddl_command_end
          WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION readiness_readonly()",
        )
        .unwrap();
    // The final CREATE INDEX turns on read-only for subsequent observations;
    // existing-index IF NOT EXISTS commands still succeed on this PG fixture.
    drop(pair);
    let mut pair = fixture.pair(64);
    let before = fixture.snapshot();
    denied(&mut pair);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn unavailable_owned_connections_fail_closed() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    fixture
        .admin
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
      WHERE usename=$1 AND datname=current_database()",
            &[&fixture.role],
        )
        .unwrap();
    let before = fixture.snapshot();
    denied(&mut pair);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn exclusive_table_lock_bounds_observation_and_does_not_claim_or_write() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    let before = fixture.snapshot();
    let mut lock = fixture.admin.transaction().unwrap();
    lock.batch_execute(
        "LOCK TABLE apex_ingest_idempotency, apex_event_outbox IN ACCESS EXCLUSIVE MODE",
    )
    .unwrap();
    let started = Instant::now();
    denied(&mut pair);
    assert!(started.elapsed() < Duration::from_secs(12));
    lock.rollback().unwrap();
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn established_postgres_socket_stalls_close_both_owned_connections_within_deadline() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let config: Config = fixture.url.parse().unwrap();
    let upstream_port = config.get_ports()[0];
    let upstream = ([127, 0, 0, 1], upstream_port).into();
    let idempotency_relay = relay::Relay::new(upstream);
    let outbox_relay = relay::Relay::new(upstream);
    let relay_url = |port| {
        fixture
            .url
            .replace(&format!("port={upstream_port} "), &format!("port={port} "))
    };
    let mut pair = (
        PostgresIdempotencyStore::connect_for_worker(&relay_url(idempotency_relay.port), 64)
            .unwrap(),
        PostgresOutbox::connect_for_worker(&relay_url(outbox_relay.port), 64).unwrap(),
    );
    ready(&mut pair);
    let before = fixture.snapshot();
    idempotency_relay.stall();
    outbox_relay.stall();
    let started = Instant::now();
    assert!(pair.0.check_admission_readiness("ws", "ns").is_err());
    assert!((Duration::from_secs(4)..Duration::from_secs(7)).contains(&started.elapsed()));
    idempotency_relay.assert_peer_closed();
    let started = Instant::now();
    assert!(pair.1.check_admission_readiness("ws", "ns").is_err());
    assert!((Duration::from_secs(4)..Duration::from_secs(7)).contains(&started.elapsed()));
    outbox_relay.assert_peer_closed();
    let started = Instant::now();
    denied(&mut pair);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "closed owners do not retry"
    );
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn legacy_connect_preserves_writes_but_cannot_claim_bounded_readiness() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut pair = (
        PostgresIdempotencyStore::connect(&fixture.url, 64).unwrap(),
        PostgresOutbox::connect(&fixture.url, 64).unwrap(),
    );
    denied(&mut pair);
    let key = IdempotencyKey {
        workspace_id: "ws".into(),
        namespace_id: "ns".into(),
        event_id: "01900000-0000-7000-8000-000000000001".into(),
    };
    let ReservationResult::Reserved(handle) = pair.0.reserve(key.clone(), [1; 32]).unwrap() else {
        panic!("legacy reserve");
    };
    pair.0.commit(handle).unwrap();
    assert_eq!(
        pair.0.reserve(key, [1; 32]).unwrap(),
        ReservationResult::Duplicate
    );
}

#[test]
fn missing_tables_fail_without_recreating_the_schema() {
    let Some(mut fixture) = Fixture::new() else {
        return;
    };
    let mut pair = fixture.pair(64);
    ready(&mut pair);
    fixture
        .admin
        .batch_execute("DROP TABLE apex_ingest_idempotency, apex_event_outbox")
        .unwrap();
    denied(&mut pair);
    let count: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM pg_class
      WHERE relnamespace='public'::regnamespace",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}
