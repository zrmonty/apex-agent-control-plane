use super::{
    fixture::{Fixture, Http},
    support,
};
use reqwest::Method;
use serde_json::{Value, json};

#[test]
fn verified_session_exposes_only_identity_exact_scopes_csrf_and_honest_capabilities() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        let response = http
            .request(Method::GET, "/api/session", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let text = response.text().await.unwrap();
        for forbidden in [
            support::TOKEN,
            "fixture-refresh-secret-canary",
            token.expose_secret(),
            "hostile-browser-secret-canary",
        ] {
            assert!(!text.contains(forbidden));
        }
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["subject"], "operator:keycloak:browser-tls-component");
        assert_eq!(body["csrfToken"], csrf.expose_secret());
        assert_eq!(
            body["scopes"],
            json!([{"workspaceId":"work","namespaceId":"ns"}])
        );
        assert_eq!(body["capabilities"]["runtimeReadiness"], "unknown");
        assert_eq!(body["capabilities"]["approvals"], false);
        assert_eq!(body["capabilities"]["traces"], false);
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}

#[test]
fn authenticated_posts_require_origin_and_csrf_before_touch_or_rpc() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        let before = http
            .sessions
            .load(token.lookup_digest())
            .await
            .unwrap()
            .unwrap();
        for (origin, csrf_value) in [
            (None, None),
            (Some("https://attacker.example"), Some(csrf.expose_secret())),
            (Some("https://console.example"), None),
            (Some("https://console.example"), Some("invalid")),
        ] {
            let mut request = http
                .request(
                    Method::POST,
                    "/api/apex/v1/McpProxyService/ListProxies",
                    &token,
                )
                .json(&json!({"workspaceId":"work","namespaceId":"ns"}));
            if let Some(value) = origin {
                request = request.header("origin", value);
            }
            if let Some(value) = csrf_value {
                request = request.header("x-apex-csrf", value);
            }
            assert_eq!(request.send().await.unwrap().status(), 403);
            let after = http
                .sessions
                .load(token.lookup_digest())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.idle_expires_at, before.idle_expires_at);
            assert_eq!(after.generation, before.generation);
        }
        assert_eq!(http.peer.state.rpc_calls(), 0);
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .json(&json!({"workspaceId":"work","namespaceId":"ns"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "{}");
        assert_eq!(http.peer.state.rpc_calls(), 1);
        assert!(http.peer.state.peer_identity_and_metadata_match());
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .json(&json!({"workspaceId":"other","namespaceId":"ns"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        http.shutdown().await;
    });
}

#[test]
fn invalid_access_or_identity_mismatch_never_discloses_session_or_calls_management() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        for (subject, access) in [
            ("browser-tls-component", "unverified-access-secret"),
            ("other-subject", support::TOKEN),
        ] {
            let (token, _) = http.seed(subject, access).await;
            let response = http
                .request(Method::GET, "/api/session", &token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
            let body = response.text().await.unwrap();
            assert!(!body.contains("csrfToken"));
            assert!(!body.contains(subject));
        }
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}
