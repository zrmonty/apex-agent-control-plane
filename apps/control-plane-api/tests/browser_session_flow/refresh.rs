use super::{
    fixture::{Fixture, Http},
    support,
};
use reqwest::Method;

#[test]
fn provider_outage_leaves_one_non_retryable_claim_and_logout_still_wins() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http
            .seed_with_lifetime("browser-tls-component", support::TOKEN, 10)
            .await;
        let response = http
            .request(Method::GET, "/api/session", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        let claimed = http
            .sessions
            .load(token.lookup_digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.generation, 1);
        assert!(claimed.refresh_deadline.is_some());
        let response = http
            .request(Method::GET, "/api/session", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        let still_claimed = http
            .sessions
            .load(token.lookup_digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_claimed.generation, 1);
        assert_eq!(still_claimed.refresh_deadline, claimed.refresh_deadline);
        assert_eq!(
            still_claimed.envelope.ciphertext(),
            claimed.envelope.ciphertext()
        );
        assert_eq!(http.peer.state.rpc_calls(), 0);
        let logout = http
            .request(Method::POST, "/auth/logout", &token)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .send()
            .await
            .unwrap();
        assert_eq!(logout.status(), 204);
        assert!(
            http.sessions
                .load(token.lookup_digest())
                .await
                .unwrap()
                .is_none()
        );
        http.shutdown().await;
    });
    let row = fixture
        .database
        .client()
        .query_one(
            "SELECT state,generation,token_ciphertext FROM apex_browser_sessions",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "revoked");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert!(row.get::<_, Option<Vec<u8>>>(2).is_none());
}

#[test]
fn malformed_rpc_cannot_claim_refresh_even_with_valid_origin_and_csrf() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (token, csrf) = http
            .seed_with_lifetime("browser-tls-component", support::TOKEN, 10)
            .await;
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .header("content-type", "application/json")
            .body("{")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
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
