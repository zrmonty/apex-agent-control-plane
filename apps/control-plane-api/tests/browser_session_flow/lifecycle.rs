use super::{
    fixture::{Fixture, Http},
    support,
};
use reqwest::Method;

#[test]
fn logout_revokes_locally_without_refresh_even_when_provider_is_unavailable() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http
            .seed_with_lifetime("browser-tls-component", support::TOKEN, 10)
            .await;
        let denied = http
            .request(Method::POST, "/auth/logout", &token)
            .header("origin", "https://console.example")
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 403);
        assert!(
            http.sessions
                .load(token.lookup_digest())
                .await
                .unwrap()
                .is_some()
        );
        let response = http
            .request(Method::POST, "/auth/logout", &token)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        let cookie = response.headers()["set-cookie"].to_str().unwrap();
        for required in [
            "__Host-apex_session=;",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=0",
        ] {
            assert!(cookie.contains(required));
        }
        assert!(!cookie.contains("Domain="));
        assert!(response.bytes().await.unwrap().is_empty());
        assert!(
            http.sessions
                .load(token.lookup_digest())
                .await
                .unwrap()
                .is_none()
        );
        let replay = http
            .request(Method::GET, "/api/session", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), 401);
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
    let row = fixture
        .database
        .client()
        .query_one(
            "SELECT state,token_ciphertext,refresh_deadline FROM apex_browser_sessions",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "revoked");
    assert!(row.get::<_, Option<Vec<u8>>>(1).is_none());
    assert!(row.get::<_, Option<i64>>(2).is_none());
}

#[test]
fn expired_durable_session_is_not_extended_or_forwarded() {
    let fixture = Fixture::new();
    let http = fixture
        .runtime
        .block_on(Http::start(fixture.sessions.clone()));
    let (token, csrf) = fixture
        .runtime
        .block_on(http.seed("browser-tls-component", support::TOKEN));
    let mut client = fixture.database.client();
    client.execute("UPDATE apex_browser_sessions SET idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint-1",&[]).unwrap();
    drop(client);
    fixture.runtime.block_on(async {
        assert_eq!(
            http.request(Method::GET, "/api/session", &token)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            http.request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .json(&serde_json::json!({"workspaceId":"work","namespaceId":"ns"}))
            .send()
            .await
            .unwrap()
            .status(),
            401
        );
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}
