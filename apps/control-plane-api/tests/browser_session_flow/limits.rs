use super::{
    fixture::{Fixture, Http},
    support,
};
use reqwest::Method;

#[test]
fn authenticated_rpc_rejects_unknown_routes_content_types_duplicate_json_and_large_bodies() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        for (path, content_type, body, status) in [
            (
                "/api/apex/v1/OtherService/ListProxies",
                "application/json",
                "{}".to_owned(),
                404,
            ),
            (
                "/api/apex/v1/McpProxyService/NotAnRpc",
                "application/json",
                "{}".to_owned(),
                404,
            ),
            (
                "/api/apex/v1/McpProxyService/ListProxies",
                "text/plain",
                "{}".to_owned(),
                415,
            ),
            (
                "/api/apex/v1/McpProxyService/ListProxies",
                "application/json",
                r#"{"workspaceId":"work","workspaceId":"other","namespaceId":"ns"}"#.to_owned(),
                400,
            ),
            (
                "/api/apex/v1/McpProxyService/ListProxies",
                "application/json",
                "x".repeat(256 * 1024 + 1),
                413,
            ),
        ] {
            let response = http
                .request(Method::POST, path, &token)
                .header("origin", "https://console.example")
                .header("x-apex-csrf", csrf.expose_secret())
                .header("content-type", content_type)
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status, "{path}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
        }
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}

#[test]
fn near_expiry_session_with_wrong_csrf_cannot_start_refresh_or_mutate_generation() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, _) = http
            .seed_with_lifetime("browser-tls-component", support::TOKEN, 10)
            .await;
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", "wrong")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let row = http
            .sessions
            .load(token.lookup_digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.generation, 0);
        assert!(row.refresh_deadline.is_none());
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}
