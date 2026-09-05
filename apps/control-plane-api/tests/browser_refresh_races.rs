//! E2 component coverage using a complete real Keycloak refresh response.
//! Requires the separately owned 18462 backend advertising the 18461 HTTPS gate.
//! This does not claim deployed browser cookie-jar or full-runtime acceptance.
#![cfg(feature = "postgres")]

use postgres::{Client, NoTls};
#[path = "browser_refresh_races/bounded_pg.rs"]
mod bounded_pg;
#[allow(dead_code)]
#[path = "browser_session_store/support.rs"]
mod database;
#[path = "browser_refresh_races/fixture.rs"]
mod fixture;
#[path = "browser_refresh_races/gate.rs"]
mod gate;
#[allow(dead_code)]
#[path = "browser_keycloak_flow/login.rs"]
mod login;
#[path = "browser_refresh_races/pg_faults.rs"]
mod pg_faults;
#[path = "browser_refresh_races/session.rs"]
mod session;
#[allow(dead_code)]
#[path = "browser_management_tls/support.rs"]
mod support;

use fixture::{Fixture, within};
use session::{assert_closed, assert_revoked, logout, near_expiry, rpc, snapshot};
use std::sync::Mutex;

// These three cases own the fixed front port for their whole lifetime. Poisoning
// must not turn one failed case into an apparent fixture failure in later cases.
static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn real_held_refresh_positive_control_commits_rotation_and_serves_management() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = fixture.start().await;
        let browser = login::Browser::new(&fixture.pki);
        let session = browser.login(&http.origin, &fixture.config.issuer).await;
        let (digest, old, subject) = near_expiry(&fixture, &http, &session).await;
        let armed = fixture.gate.hold_next_refresh();
        let request = rpc(&http, &session, &old);
        let pending = support::TestTask::spawn(async move { request.send().await.unwrap() });
        let held = armed.completed().await;
        let verified = held.validate(&fixture, &old, &subject).await;
        let claimed = snapshot(&fixture, digest).await;
        assert_eq!(claimed.state, "refreshing");
        assert_eq!(claimed.generation, 1);
        assert!(claimed.deadline.is_some() && claimed.has_ciphertext);
        assert_eq!(http.management_calls(), 0);
        held.release();

        let response = within(pending.join()).await;
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("set-cookie"));
        let row = fixture.sessions.load(digest).await.unwrap().unwrap();
        assert_eq!(row.generation, 1);
        assert!(row.refresh_deadline.is_none());
        let current = session::open(&fixture, &http, &row);
        assert!(current.refresh.as_str() == verified.refresh.as_str());
        assert!(current.access.as_str() == verified.access.as_str());
        assert!(current.refresh.as_str() != old.refresh.as_str());
        assert!(current.nonce.expose_secret() == old.nonce.expose_secret());
        assert!(current.csrf.expose_secret() == old.csrf.expose_secret());
        assert!(current.access_expires_at > old.access_expires_at);
        assert!(current.access_expires_at <= verified.signed_expiry);
        assert_eq!(http.management_calls(), 1);

        let response = http
            .client
            .get(format!("{}/api/session", http.origin))
            .header("cookie", &session.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        for token in [&current.access, &current.refresh] {
            assert!(!body.contains(token.as_str()));
        }
        for name in ["access_token", "refresh_token", "id_token"] {
            assert!(!body.contains(name));
        }
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
        logout(&http, &session, &current).await;
        assert_revoked(&fixture, digest).await;
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}

#[test]
fn logout_before_real_rotated_reply_forces_late_401_without_resurrection_or_forward() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = fixture.start().await;
        let browser = login::Browser::new(&fixture.pki);
        let session = browser.login(&http.origin, &fixture.config.issuer).await;
        let (digest, old, subject) = near_expiry(&fixture, &http, &session).await;
        let armed = fixture.gate.hold_next_refresh();
        let request = rpc(&http, &session, &old);
        let pending = support::TestTask::spawn(async move { request.send().await.unwrap() });
        let held = armed.completed().await;
        // This authentic reply has already rotated at Keycloak. Validate its
        // access and ID token independently before allowing logout to race CAS.
        let _verified = held.validate(&fixture, &old, &subject).await;
        let claimed = snapshot(&fixture, digest).await;
        assert_eq!(claimed.state, "refreshing");
        assert_eq!(claimed.generation, 1);
        assert!(claimed.deadline.is_some() && claimed.has_ciphertext);
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
        assert_eq!(http.management_calls(), 0);

        logout(&http, &session, &old).await;
        assert_revoked(&fixture, digest).await;
        assert_eq!(fixture.gate.revocations(), 1);
        held.release();
        let response = within(pending.join()).await;
        // 503 is not success: it would hide a transport/provider/claim timeout.
        assert_eq!(response.status(), 401);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_revoked(&fixture, digest).await;
        assert_closed(&fixture, &http, &session, &old, 401).await;
        assert_eq!(http.management_calls(), 0);
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}

#[test]
fn lost_real_rotated_reply_never_retries_or_reclaims_and_logout_still_revokes() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = fixture.start().await;
        let browser = login::Browser::new(&fixture.pki);
        let session = browser.login(&http.origin, &fixture.config.issuer).await;
        let (digest, old, subject) = near_expiry(&fixture, &http, &session).await;
        let armed = fixture.gate.hold_next_refresh();
        let request = rpc(&http, &session, &old);
        let pending = support::TestTask::spawn(async move { request.send().await.unwrap() });
        let held = armed.completed().await;
        let _verified = held.validate(&fixture, &old, &subject).await;
        let claimed = snapshot(&fixture, digest).await;
        assert_eq!(claimed.state, "refreshing");
        assert_eq!(claimed.generation, 1);
        assert!(claimed.deadline.is_some() && claimed.has_ciphertext);
        held.lose_reply();

        let response = within(pending.join()).await;
        assert_eq!(response.status(), 503);
        assert!(!response.headers().contains_key("set-cookie"));
        // Repeated valid session/RPC requests cannot spend the old token again.
        // Neither old nor rotated refresh tokens are probed against Keycloak.
        assert_closed(&fixture, &http, &session, &old, 503).await;
        let after = snapshot(&fixture, digest).await;
        assert_eq!(after, claimed);
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
        assert_eq!(http.management_calls(), 0);

        logout(&http, &session, &old).await;
        assert_revoked(&fixture, digest).await;
        assert_eq!(fixture.gate.revocations(), 1);
        assert_closed(&fixture, &http, &session, &old, 401).await;
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
        assert_eq!(http.management_calls(), 0);
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}
