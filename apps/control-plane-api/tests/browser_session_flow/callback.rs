use super::fixture::{Fixture, Http};
use apex_control_plane_api::browser::security::OpaqueToken;

#[test]
fn callback_denial_and_wrong_issuer_consume_only_the_matched_browser_attempt() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        for suffix in [
            "error=access_denied&error_description=provider-secret-canary",
            "code=one-use-code&iss=https%3A%2F%2Fattacker.invalid",
        ] {
            let (state, browser) = http.seed_login().await;
            let url = format!(
                "{}/auth/callback?state={}&{suffix}",
                http.origin,
                state.expose_secret()
            );
            let response = http
                .client
                .get(&url)
                .header(
                    "cookie",
                    format!("__Host-apex_login={}", browser.expose_secret()),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            let body = response.text().await.unwrap();
            for secret in [
                "provider-secret-canary",
                "one-use-code",
                state.expose_secret(),
                browser.expose_secret(),
                "attacker.invalid",
            ] {
                assert!(!body.contains(secret));
            }
            assert!(
                http.sessions
                    .take_login(state.lookup_digest(), browser.lookup_digest())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}

#[test]
fn wrong_browser_binding_cannot_consume_a_legitimate_callback_attempt() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (state, browser) = http.seed_login().await;
        let attacker = OpaqueToken::generate().unwrap();
        let response = http
            .client
            .get(format!(
                "{}/auth/callback?state={}&code=one-use-code",
                http.origin,
                state.expose_secret()
            ))
            .header(
                "cookie",
                format!("__Host-apex_login={}", attacker.expose_secret()),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        assert!(
            http.sessions
                .take_login(state.lookup_digest(), browser.lookup_digest())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
}

#[test]
fn callback_is_one_use_even_when_the_provider_cannot_exchange_the_code() {
    let fixture = Fixture::new();
    fixture.runtime.block_on(async {
        let http = Http::start(fixture.sessions.clone()).await;
        let (state, browser) = http.seed_login().await;
        let url = format!(
            "{}/auth/callback?state={}&code=one-use-code",
            http.origin,
            state.expose_secret()
        );
        for expected in [503, 401] {
            let response = http
                .client
                .get(&url)
                .header(
                    "cookie",
                    format!("__Host-apex_login={}", browser.expose_secret()),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
            assert!(response.headers().get("location").is_none());
            assert!(response.headers().get("set-cookie").is_none());
        }
        assert!(
            http.sessions
                .take_login(state.lookup_digest(), browser.lookup_digest())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
    let count: i64 = fixture
        .database
        .client()
        .query_one("SELECT count(*) FROM apex_browser_sessions", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}
