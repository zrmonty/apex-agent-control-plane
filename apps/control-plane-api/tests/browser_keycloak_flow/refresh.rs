use super::{
    fixture::{Fixture, Http},
    login::{Browser, Session},
};
use apex_control_plane_api::browser::{
    bundle::SessionBundle,
    errors::BrowserError,
    security::{LookupDigest, OpaqueToken},
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// Fault injection into this test's UUID-named schema only. Shorten the copied
// access expiry and reauthenticate its protected payload; never extend a signed
// credential, change its grants or fabricate a provider response. This avoids a
// four-minute CI sleep while the actual one-use refresh runs against Keycloak.
fn near_expiry(fixture: &Fixture, http: &Http, session: &Session) -> (LookupDigest, SessionBundle) {
    let token =
        OpaqueToken::parse(session.cookie.strip_prefix("__Host-apex_session=").unwrap()).unwrap();
    let digest = token.lookup_digest();
    let row = fixture
        .runtime
        .block_on(fixture.sessions.load(digest))
        .unwrap()
        .unwrap();
    let mut payload = SessionBundle::open(&row, &fixture.config(), &http.keys, now()).unwrap();
    payload.access_expires_at = now() + 10;
    let envelope = payload.seal(&row.identity, &http.keys, now()).unwrap();
    let affected=fixture.database.client().execute("UPDATE apex_browser_sessions SET access_expires_at=$2,token_ciphertext=$3,token_nonce=$4 WHERE session_digest=$1",
        &[&digest.as_bytes().as_slice(),&payload.access_expires_at,&envelope.ciphertext(),&envelope.nonce().as_slice()]).unwrap();
    assert_eq!(affected, 1);
    (digest, payload)
}

#[test]
fn concurrent_real_requests_share_one_refresh_generation() {
    let fixture = Fixture::new();
    let http = fixture.runtime.block_on(fixture.start());
    let browser = Browser::new(&fixture.pki);
    let session = fixture
        .runtime
        .block_on(browser.login(&http.origin, &fixture.issuer));
    let (digest, old) = near_expiry(&fixture, &http, &session);
    fixture.runtime.block_on(async {
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let request = http
                .client
                .get(format!("{}/api/session", http.origin))
                .header("cookie", &session.cookie);
            requests.spawn(async move { request.send().await.unwrap().status().as_u16() });
        }
        let mut successes = 0;
        while let Some(status) = requests.join_next().await {
            match status.unwrap() {
                200 => successes += 1,
                // Explicit busy/unavailable, never a retry of the old token.
                429 | 503 => {}
                status => panic!("unexpected refresh contender status {status}"),
            }
        }
        assert!(successes >= 1);
        let row = fixture.sessions.load(digest).await.unwrap().unwrap();
        assert_eq!(row.generation, 1);
        assert!(row.refresh_deadline.is_none());
        let current = SessionBundle::open(&row, &fixture.config(), &http.keys, now()).unwrap();
        assert!(current.refresh.as_str() != old.refresh.as_str());
        let response = http
            .client
            .post(format!(
                "{}/api/apex/v1/McpProxyService/ListProxies",
                http.origin
            ))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", current.csrf.expose_secret())
            .json(&serde_json::json!({"workspaceId":"acme","namespaceId":"prod"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}

#[test]
fn real_keycloak_refresh_rotates_under_one_generation_and_old_refresh_is_rejected() {
    let fixture = Fixture::new();
    let http = fixture.runtime.block_on(fixture.start());
    let browser = Browser::new(&fixture.pki);
    let session = fixture
        .runtime
        .block_on(browser.login(&http.origin, &fixture.issuer));
    let (digest, old) = near_expiry(&fixture, &http, &session);
    fixture.runtime.block_on(async {
        let response = http
            .client
            .get(format!("{}/api/session", http.origin))
            .header("cookie", &session.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "near-expiry request must complete a fenced real refresh"
        );
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["csrfToken"].as_str() == Some(old.csrf.expose_secret()));
        let row = fixture.sessions.load(digest).await.unwrap().unwrap();
        assert_eq!(row.generation, 1);
        assert!(row.refresh_deadline.is_none());
        let current = SessionBundle::open(&row, &fixture.config(), &http.keys, now()).unwrap();
        assert!(current.refresh.as_str() != old.refresh.as_str());
        assert!(current.nonce.expose_secret() == old.nonce.expose_secret());
        assert!(current.access_expires_at > old.access_expires_at);
        // Deliberate negative IdP operation against disposable lab credentials,
        // after proving the current persisted session, never an automatic retry.
        assert!(matches!(
            http.provider
                .refresh(
                    &old.refresh,
                    &row.identity.subject,
                    old.nonce.expose_secret()
                )
                .await,
            Err(BrowserError::Unauthenticated)
        ));
        let response = http
            .client
            .post(format!("{}/auth/logout", http.origin))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", current.csrf.expose_secret())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        assert!(fixture.sessions.load(digest).await.unwrap().is_none());
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}

#[test]
fn near_expiry_real_session_still_requires_csrf_before_any_refresh_claim() {
    let fixture = Fixture::new();
    let http = fixture.runtime.block_on(fixture.start());
    let browser = Browser::new(&fixture.pki);
    let session = fixture
        .runtime
        .block_on(browser.login(&http.origin, &fixture.issuer));
    let (digest, old) = near_expiry(&fixture, &http, &session);
    fixture.runtime.block_on(async {
        let response = http
            .client
            .post(format!(
                "{}/api/apex/v1/McpProxyService/ListProxies",
                http.origin
            ))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", "wrong")
            .json(&serde_json::json!({"workspaceId":"acme","namespaceId":"prod"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let row = fixture.sessions.load(digest).await.unwrap().unwrap();
        assert_eq!(row.generation, 0);
        assert!(row.refresh_deadline.is_none());
        let current = SessionBundle::open(&row, &fixture.config(), &http.keys, now()).unwrap();
        assert!(current.refresh.as_str() == old.refresh.as_str());
        assert_eq!(current.access_expires_at, old.access_expires_at);
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
}
