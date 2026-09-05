#![cfg(feature = "postgres")]
//! Required real PostgreSQL actor integration, not HTTP/OIDC acceptance.
//! Startup, async facade behavior and actual PostgreSQL owner cleanup.

use apex_control_plane_api::browser::{
    crypto::{EnvelopePurpose, RecordDigest, TokenBinding, TokenKey, TokenKeyring},
    security::LookupDigest,
    sessions::{BrowserSessionStore, NewLoginAttempt},
};
use postgres::{Client, NoTls};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// This existing fixture requires the environment variable and an owned loopback
// database. Fixture setup, its synchronous observer and teardown stay off Tokio.
#[path = "browser_session_store/support.rs"]
mod browser_session_store_support;
use browser_session_store_support::Database;

#[path = "browser_session_worker/admission.rs"]
mod admission;
#[path = "browser_session_worker/lifecycle.rs"]
mod lifecycle;
#[path = "browser_session_worker/operations.rs"]
mod operations;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn worker_url(database: &Database) -> (String, String) {
    let name = format!("browser_worker_{}", uuid::Uuid::now_v7().simple());
    (format!("{}&application_name={name}", database.url), name)
}

fn observer(database: &Database) -> Client {
    let mut observer = database.client();
    observer
        .batch_execute("SET statement_timeout='1s'")
        .unwrap();
    observer
}

fn wait_closed(observer: &mut Client, application_name: &str) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while connection_count(observer, application_name) != 0 {
        assert!(
            Instant::now() < deadline,
            "worker must close its PostgreSQL connection"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock after Unix epoch")
            .as_secs(),
    )
    .expect("test clock fits PostgreSQL timestamp")
}

fn login_attempt(state: LookupDigest, browser: LookupDigest) -> NewLoginAttempt {
    let expires_at = now() + 300;
    let keys = TokenKeyring::new(vec![
        TokenKey::active("worker-fixture", Zeroizing::new([9; 32])).unwrap(),
    ])
    .unwrap();
    let binding = TokenBinding::new(
        EnvelopePurpose::LoginAttempt,
        RecordDigest::from_sha256(state.as_bytes()).unwrap(),
        "https://issuer.example/realm",
        "apex-browser",
        None,
        expires_at,
    )
    .unwrap();
    NewLoginAttempt {
        state,
        browser,
        issuer: "https://issuer.example/realm".into(),
        client_id: "apex-browser".into(),
        expires_at,
        envelope: keys.seal(b"worker-login-fixture", &binding, now()).unwrap(),
    }
}

fn connection_count(observer: &mut Client, application_name: &str) -> i64 {
    assert!(tokio::runtime::Handle::try_current().is_err());
    observer
        .query_one(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname=current_database() AND application_name=$1",
            &[&application_name],
        )
        .expect("observe only this test's worker connection")
        .get(0)
}

#[test]
fn real_postgres_login_round_trip_and_last_owner_drop_are_safe_on_tokio() {
    let database = Database::new();
    let mut observer = database.client();
    observer
        .batch_execute("SET statement_timeout='1s'")
        .unwrap();
    let application_name = format!("browser_worker_{}", uuid::Uuid::now_v7().simple());
    let connection_string = format!("{}&application_name={application_name}", database.url);

    // Startup is deliberately synchronous and outside any entered runtime.
    assert!(tokio::runtime::Handle::try_current().is_err());
    let store = BrowserSessionStore::connect(&connection_string)
        .expect("browser session actor must initialize its PostgreSQL owner");
    assert_eq!(
        connection_count(&mut observer, &application_name),
        1,
        "startup must own one real PostgreSQL connection"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = LookupDigest::from_bytes([1; 32]);
    let browser = LookupDigest::from_bytes([2; 32]);
    let input = login_attempt(state, browser);
    let expected_expiry = input.expires_at;
    let expected_ciphertext = input.envelope.ciphertext().to_vec();

    // Both facade owners live in this future: no synchronous keepalive can hide
    // a PostgreSQL/runtime destructor accidentally running on the Tokio thread.
    runtime.block_on(async move {
        tokio::time::timeout(Duration::from_secs(6), async move {
            store.create_login(input).await.unwrap();
            let remaining = store.clone();
            drop(store);
            let taken = remaining
                .take_login(state, browser)
                .await
                .unwrap()
                .expect("a clone must read the committed login attempt");
            assert_eq!(taken.state, state);
            assert_eq!(taken.browser, browser);
            assert_eq!(taken.issuer, "https://issuer.example/realm");
            assert_eq!(taken.client_id, "apex-browser");
            assert_eq!(taken.expires_at, expected_expiry);
            assert_eq!(taken.envelope.ciphertext(), expected_ciphertext.as_slice());
            assert!(
                remaining
                    .take_login(state, browser)
                    .await
                    .unwrap()
                    .is_none()
            );

            let dropped_at = Instant::now();
            drop(remaining);
            assert!(
                dropped_at.elapsed() < Duration::from_millis(250),
                "last facade drop must promptly release the Tokio thread"
            );
        })
        .await
        .expect("async login round trip must complete within a bounded wait");
    });

    // Observe actual socket/PG owner release, rather than treating absence of a
    // panic as cleanup. Six seconds allows the five-second transport deadline.
    let deadline = Instant::now() + Duration::from_secs(6);
    while connection_count(&mut observer, &application_name) != 0 {
        assert!(Instant::now() < deadline, "last drop leaked its PG owner");
        std::thread::sleep(Duration::from_millis(20));
    }
}
