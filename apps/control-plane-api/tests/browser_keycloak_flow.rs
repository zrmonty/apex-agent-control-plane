//! Real Keycloak HTTPS code flow through the browser edge. This is a component
//! integration test, not the deployed UI/runtime release gate. No static JWTs,
//! fabricated provider responses or skipped missing-service paths are allowed.
#![cfg(feature = "postgres")]
use postgres::{Client, NoTls};
#[path = "browser_session_store/support.rs"]
mod database;
#[path = "browser_keycloak_flow/fixture.rs"]
mod fixture;
#[path = "browser_keycloak_flow/login.rs"]
mod login;
#[path = "browser_keycloak_flow/refresh.rs"]
mod refresh;
#[allow(dead_code)]
#[path = "browser_management_tls/support.rs"]
mod support;

#[test]
fn real_keycloak_code_pkce_login_creates_opaque_session_and_scoped_management_access() {
    let fixture = fixture::Fixture::new();
    fixture.runtime.block_on(async {
        let http = fixture.start().await;
        let browser = login::Browser::new(&fixture.pki);
        let session = browser.login(&http.origin, &fixture.issuer).await;
        let response = http
            .client
            .get(format!("{}/api/session", http.origin))
            .header("cookie", &session.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let text = response.text().await.unwrap();
        assert!(!text.contains("access_token"));
        assert!(!text.contains("refresh_token"));
        assert!(!text.contains("id_token"));
        assert!(!text.contains(session.cookie.split('=').nth(1).unwrap()));
        let result: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            result["subject"]
                .as_str()
                .unwrap()
                .starts_with("operator:keycloak:")
        );
        assert_eq!(
            result["scopes"],
            serde_json::json!([{"workspaceId":"acme","namespaceId":"prod"}])
        );
        let csrf = result["csrfToken"].as_str().unwrap();
        for (workspace, status) in [("acme", 200), ("unauthorized", 403)] {
            let response = http
                .client
                .post(format!(
                    "{}/api/apex/v1/McpProxyService/ListProxies",
                    http.origin
                ))
                .header("cookie", &session.cookie)
                .header("origin", "https://console.example")
                .header("x-apex-csrf", csrf)
                .header(
                    "authorization",
                    "Bearer hostile-browser-token-not-forwarded",
                )
                .json(&serde_json::json!({"workspaceId":workspace,"namespaceId":"prod"}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
        // State is consumed before token exchange and cannot be replayed into
        // another session, even with the original login binding cookie.
        let replay = http
            .client
            .get(&session.callback)
            .header("cookie", &session.login_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), 401);
        let response = http
            .client
            .post(format!("{}/auth/logout", http.origin))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        assert_eq!(
            http.client
                .get(format!("{}/api/session", http.origin))
                .header("cookie", &session.cookie)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        http.shutdown().await;
        fixture.sessions.shutdown().await.unwrap();
    });
    let row = fixture
        .database
        .client()
        .query_one(
            "SELECT count(*),count(token_ciphertext) FROM apex_browser_sessions",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 0);
}
