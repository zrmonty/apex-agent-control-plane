//! Copied-expiry injection and independent PostgreSQL observations, UUID schema only.
use super::{
    bounded_pg,
    fixture::{Fixture, Http, within},
    login::Session,
};
use apex_control_plane_api::browser::{
    bundle::SessionBundle,
    security::{LookupDigest, OpaqueToken},
    sessions::StoredSession,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

pub fn open(fixture: &Fixture, http: &Http, row: &StoredSession) -> SessionBundle {
    SessionBundle::open(row, &fixture.config, &http.keys, now()).unwrap()
}

pub async fn near_expiry(
    fixture: &Fixture,
    http: &Http,
    session: &Session,
) -> (LookupDigest, SessionBundle, String) {
    let digest = OpaqueToken::parse(session.cookie.strip_prefix("__Host-apex_session=").unwrap())
        .unwrap()
        .lookup_digest();
    let row = fixture.sessions.load(digest).await.unwrap().unwrap();
    assert_eq!(row.generation, 0);
    assert!(row.refresh_deadline.is_none());
    let mut old = open(fixture, http, &row);
    let expiry = now() + 10;
    assert!(expiry < old.access_expires_at);
    // Only copied expiry changes. Signed credentials, grants, identity, nonce,
    // generation and deadlines stay authentic; no provider fake or JWT edit.
    old.access_expires_at = expiry;
    let envelope = old.seal(&row.identity, &http.keys, now()).unwrap();
    let url = fixture.database.url.clone();
    let affected = bounded_pg::run(url, move |client| {
        client.execute("UPDATE apex_browser_sessions SET access_expires_at=$2,
            token_ciphertext=$3,token_nonce=$4 WHERE session_digest=$1 AND generation=0 AND state='active'",
            &[&digest.as_bytes().as_slice(), &expiry, &envelope.ciphertext(), &envelope.nonce().as_slice()])
            .unwrap()
    }).await;
    assert_eq!(affected, 1);
    (digest, old, row.identity.subject)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub state: String,
    pub generation: i64,
    pub deadline: Option<i64>,
    pub has_ciphertext: bool,
    cleared: bool,
    total: i64,
}

pub async fn snapshot(fixture: &Fixture, digest: LookupDigest) -> Snapshot {
    snapshot_at(fixture.database.url.clone(), digest).await
}

// The fault regression exercises the actual observation operation, directing
// only this private test helper to its owned loopback PostgreSQL transport peer.
pub(super) async fn snapshot_at(url: String, digest: LookupDigest) -> Snapshot {
    bounded_pg::run(url, move |client| {
        let row = client.query_one("SELECT state,generation,refresh_deadline,
            token_ciphertext IS NOT NULL,
            token_ciphertext IS NULL AND token_nonce IS NULL AND token_key_id IS NULL AND token_version IS NULL,
            (SELECT count(*) FROM apex_browser_sessions)
            FROM apex_browser_sessions WHERE session_digest=$1", &[&digest.as_bytes().as_slice()]).unwrap();
        Snapshot { state: row.get(0), generation: row.get(1), deadline: row.get(2),
            has_ciphertext: row.get(3), cleared: row.get(4), total: row.get(5) }
    }).await
}

pub async fn assert_revoked(fixture: &Fixture, digest: LookupDigest) {
    let row = snapshot(fixture, digest).await;
    assert_eq!(row.state, "revoked");
    assert_eq!(row.generation, 1);
    assert!(row.deadline.is_none());
    assert!(!row.has_ciphertext && row.cleared);
    assert_eq!(row.total, 1, "no replacement row may be inserted");
    assert!(fixture.sessions.load(digest).await.unwrap().is_none());
}

pub fn rpc(http: &Http, session: &Session, old: &SessionBundle) -> reqwest::RequestBuilder {
    http.client
        .post(format!(
            "{}/api/apex/v1/McpProxyService/ListProxies",
            http.origin
        ))
        .header("cookie", &session.cookie)
        .header("origin", "https://console.example")
        .header("x-apex-csrf", old.csrf.expose_secret())
        .json(&serde_json::json!({"workspaceId":"acme","namespaceId":"prod"}))
}

pub async fn logout(http: &Http, session: &Session, old: &SessionBundle) {
    let response = within(
        http.client
            .post(format!("{}/auth/logout", http.origin))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", old.csrf.expose_secret())
            .send(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 204);
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies.len(), 1);
    let cookie = cookies[0].to_str().unwrap();
    assert!(cookie.starts_with("__Host-apex_session=;"));
    for part in [
        "Max-Age=0",
        "; Secure",
        "; HttpOnly",
        "; SameSite=Lax",
        "; Path=/",
    ] {
        assert!(cookie.contains(part));
    }
}

pub async fn assert_closed(
    fixture: &Fixture,
    http: &Http,
    session: &Session,
    old: &SessionBundle,
    status: u16,
) {
    for _ in 0..2 {
        let response = within(
            http.client
                .get(format!("{}/api/session", http.origin))
                .header("cookie", &session.cookie)
                .send(),
        )
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert!(!response.headers().contains_key("set-cookie"));
        let response = within(rpc(http, session, old).send()).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(fixture.gate.refresh_counts(), (1, 1));
    }
}
