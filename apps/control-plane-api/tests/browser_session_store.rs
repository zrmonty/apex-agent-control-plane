#![cfg(feature = "postgres")]
//! Required real PostgreSQL store tests, not complete HTTP/OIDC login acceptance.
use apex_control_plane_api::browser::{crypto::*, security::*, sessions::*};
use postgres::{Client, NoTls};
use std::{
    sync::{Arc, Barrier},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[path = "browser_session_store/support.rs"]
mod browser_session_store_support;
use browser_session_store_support::Database;

#[path = "browser_session_store/admission_schema.rs"]
mod admission_schema;
#[path = "browser_session_store/capacity.rs"]
mod capacity;
#[path = "browser_session_store/expiry_races.rs"]
mod expiry_races;
#[path = "browser_session_store/host_policy.rs"]
mod host_policy;
#[path = "browser_session_store/regression_support.rs"]
mod regression_support;
#[path = "browser_session_store/schema_drift.rs"]
mod schema_drift;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}
fn digest(byte: u8) -> LookupDigest {
    LookupDigest::from_bytes([byte; 32])
}
fn envelope(digest: LookupDigest, purpose: EnvelopePurpose, expires: i64) -> TokenEnvelope {
    let keys = TokenKeyring::new(vec![
        TokenKey::active("fixture-key", Zeroizing::new([9; 32])).unwrap(),
    ])
    .unwrap();
    let subject = (purpose == EnvelopePurpose::OperatorSession).then_some("operator:keycloak:test");
    let binding = TokenBinding::new(
        purpose,
        RecordDigest::from_sha256(digest.as_bytes()).unwrap(),
        "https://issuer.example/realm",
        "apex-browser",
        subject,
        expires,
    )
    .unwrap();
    keys.seal(b"provider-secret-canary", &binding, now())
        .unwrap()
}
fn session(key: LookupDigest, access_delta: i64) -> NewSession {
    let expires = now() + 3600;
    NewSession {
        identity: SessionIdentity {
            digest: key,
            issuer: "https://issuer.example/realm".into(),
            client_id: "apex-browser".into(),
            subject: "operator:keycloak:test".into(),
            absolute_expires_at: expires,
        },
        csrf_binding: CsrfBinding::from_bytes([5; 32]),
        envelope: envelope(key, EnvelopePurpose::OperatorSession, expires),
        access_expires_at: now() + access_delta,
        refresh_expires_at: now() + 3600,
        idle_timeout_secs: 600,
    }
}
fn refreshed(key: LookupDigest, generation: u64, expires: i64) -> RefreshCommit {
    RefreshCommit {
        digest: key,
        generation,
        envelope: envelope(key, EnvelopePurpose::OperatorSession, expires),
        access_expires_at: now() + 300,
        refresh_expires_at: now() + 3600,
    }
}

#[test]
fn login_attempt_is_browser_bound_and_atomically_consumed_across_replicas() {
    let db = Database::new();
    let mut first = PostgresSessionStore::connect(&db.url).unwrap();
    let mut second = PostgresSessionStore::connect(&db.url).unwrap();
    let expires = now() + 300;
    first
        .create_login(NewLoginAttempt {
            state: digest(1),
            browser: digest(2),
            issuer: "https://issuer.example/realm".into(),
            client_id: "apex-browser".into(),
            expires_at: expires,
            envelope: envelope(digest(1), EnvelopePurpose::LoginAttempt, expires),
        })
        .unwrap();
    assert!(second.take_login(digest(1), digest(3)).unwrap().is_none());
    let taken = first.take_login(digest(1), digest(2)).unwrap().unwrap();
    assert_eq!(taken.expires_at, expires);
    assert!(second.take_login(digest(1), digest(2)).unwrap().is_none());
    assert!(first.take_login(digest(1), digest(2)).unwrap().is_none());
}

#[test]
fn session_survives_reconnect_reads_do_not_touch_and_logout_erases_credentials() {
    let db = Database::new();
    let key = digest(4);
    let mut first = PostgresSessionStore::connect(&db.url).unwrap();
    first.create_session(session(key, 300)).unwrap();
    let before = first.load(key).unwrap().unwrap();
    drop(first);
    let mut restarted = PostgresSessionStore::connect(&db.url).unwrap();
    let after = restarted.load(key).unwrap().unwrap();
    assert_eq!(before.envelope.ciphertext(), after.envelope.ciphertext());
    assert_eq!(before.idle_expires_at, after.idle_expires_at);
    assert_eq!(after.identity.subject, "operator:keycloak:test");
    assert!(restarted.load(digest(99)).unwrap().is_none());
    assert!(restarted.touch(key, 0, 600).unwrap());
    assert_eq!(
        restarted
            .load(key)
            .unwrap()
            .unwrap()
            .identity
            .absolute_expires_at,
        before.identity.absolute_expires_at
    );
    assert!(restarted.revoke(key).unwrap());
    assert!(restarted.load(key).unwrap().is_none());
    assert!(!restarted.touch(key, 0, 600).unwrap());
    let row=db.client().query_one("SELECT state, token_ciphertext IS NULL AS cleared FROM apex_browser_sessions WHERE session_digest=$1", &[&key.as_bytes().as_slice()]).unwrap();
    assert_eq!(row.get::<_, String>("state"), "revoked");
    assert!(row.get::<_, bool>("cleared"));
}

#[test]
fn competing_refresh_claims_have_one_generation_and_stale_commit_cannot_win() {
    let db = Database::new();
    let key = digest(6);
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    store.create_session(session(key, 15)).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let url = db.url.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = PostgresSessionStore::connect(&url).unwrap();
                barrier.wait();
                store.claim_refresh(key, 0).unwrap()
            })
        })
        .collect();
    let claimed: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(claimed.len(), 1);
    let claim = &claimed[0];
    assert_eq!(claim.generation, 1);
    assert!(claim.refresh_deadline.is_some());
    assert!(
        !store
            .finish_refresh(refreshed(key, 0, claim.identity.absolute_expires_at))
            .unwrap()
    );
    assert!(
        store
            .finish_refresh(refreshed(key, 1, claim.identity.absolute_expires_at))
            .unwrap()
    );
    assert!(
        !store
            .finish_refresh(refreshed(key, 1, claim.identity.absolute_expires_at))
            .unwrap()
    );
    let loaded = store.load(key).unwrap().unwrap();
    assert_eq!(loaded.generation, 1);
    assert!(loaded.refresh_deadline.is_none());
    assert!(!store.touch(key, 0, 600).unwrap());
    assert!(store.touch(key, 1, 600).unwrap());
}

#[test]
fn logout_wins_over_a_late_refresh_result() {
    let db = Database::new();
    let key = digest(7);
    let mut first = PostgresSessionStore::connect(&db.url).unwrap();
    let mut second = PostgresSessionStore::connect(&db.url).unwrap();
    first.create_session(session(key, 15)).unwrap();
    let claim = first.claim_refresh(key, 0).unwrap().unwrap();
    assert!(second.revoke(key).unwrap());
    assert!(
        !first
            .finish_refresh(refreshed(
                key,
                claim.generation,
                claim.identity.absolute_expires_at
            ))
            .unwrap()
    );
    assert!(first.load(key).unwrap().is_none());
}

#[test]
fn expired_and_abandoned_refreshes_never_reuse_the_old_token() {
    let db = Database::new();
    let key = digest(8);
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    store.create_session(session(key, 15)).unwrap();
    let claim = store.claim_refresh(key, 0).unwrap().unwrap();
    db.client().execute("UPDATE apex_browser_sessions SET refresh_deadline=extract(epoch from clock_timestamp())::bigint-1 WHERE session_digest=$1", &[&key.as_bytes().as_slice()]).unwrap();
    assert!(store.load(key).unwrap().is_none());
    assert!(store.claim_refresh(key, 1).unwrap().is_none());
    assert!(
        !store
            .finish_refresh(refreshed(key, 1, claim.identity.absolute_expires_at))
            .unwrap()
    );
    let healthy = digest(9);
    store.create_session(session(healthy, 300)).unwrap();
    // Creation performs bounded cleanup before enforcing its storage quota.
    let abandoned: i64 = db
        .client()
        .query_one(
            "SELECT count(*) FROM apex_browser_sessions WHERE session_digest=$1",
            &[&key.as_bytes().as_slice()],
        )
        .unwrap()
        .get(0);
    assert_eq!(abandoned, 0);
    db.client().execute("UPDATE apex_browser_sessions SET idle_expires_at=extract(epoch from clock_timestamp())::bigint-1 WHERE session_digest=$1", &[&healthy.as_bytes().as_slice()]).unwrap();
    assert!(store.load(healthy).unwrap().is_none());
    assert!(!store.touch(healthy, 0, 600).unwrap());
    assert_eq!(store.prune_expired().unwrap(), 1);
    assert_eq!(
        db.client()
            .query_one("SELECT count(*) FROM apex_browser_sessions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

#[test]
fn incompatible_schema_is_rejected_before_any_session_ddl() {
    for marker in [
        "CREATE TABLE apex_browser_session_schema(version INTEGER NOT NULL); INSERT INTO apex_browser_session_schema VALUES(3)",
        "CREATE TABLE apex_browser_session_schema(version INTEGER NOT NULL)",
    ] {
        let db = Database::new();
        db.client().batch_execute(marker).unwrap();
        assert!(PostgresSessionStore::connect(&db.url).is_err());
        let row=db.client().query_one("SELECT to_regclass('apex_browser_sessions') IS NULL, to_regclass('apex_browser_login_attempts') IS NULL", &[]).unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(row.get::<_, bool>(1));
    }
}

#[test]
fn malformed_lifetimes_and_colliding_identifiers_never_replace_existing_records() {
    let db = Database::new();
    let mut store = PostgresSessionStore::connect(&db.url).unwrap();
    let key = digest(10);
    store.create_session(session(key, 300)).unwrap();
    let original = store.load(key).unwrap().unwrap();
    assert!(store.create_session(session(key, 300)).is_err());
    assert_eq!(
        store.load(key).unwrap().unwrap().envelope.ciphertext(),
        original.envelope.ciphertext()
    );
    for idle in [0, 59, 3601, u32::MAX] {
        let mut invalid = session(digest(11), 300);
        invalid.idle_timeout_secs = idle;
        assert!(store.create_session(invalid).is_err());
    }
    let mut invalid = session(digest(12), 300);
    invalid.identity.absolute_expires_at = now() - 1;
    assert!(store.create_session(invalid).is_err());
    let mut invalid = session(digest(13), 300);
    invalid.identity.absolute_expires_at = now() + 86401;
    assert!(store.create_session(invalid).is_err());
}
