//! Real HTTP and PostgreSQL component flow, growing toward full Task3 coverage.
//! This initial checkpoint proves unauthenticated routing/headers, not a live
//! Keycloak login or the external HTTPS edge. Management uses real mTLS.
#![cfg(feature = "postgres")]
use apex_control_plane_api::browser::{
    crypto::{TokenKey, TokenKeyring},
    edge::{BrowserConfig, BrowserDependencies, BrowserEdge},
    oidc::{OidcProvider, config::OidcConfig},
    sessions::BrowserSessionStore,
};
use postgres::{Client, NoTls};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

// Reuse existing disposable fixtures; their unrelated helper entry points are
// exercised by browser_management_tls, not all by this focused HTTP checkpoint.
#[path = "browser_session_flow/authenticated.rs"]
mod authenticated;
#[path = "browser_session_flow/callback.rs"]
mod callback;
#[path = "browser_session_store/support.rs"]
mod database;
#[path = "browser_session_flow/fixture.rs"]
mod fixture;
#[path = "browser_session_flow/lifecycle.rs"]
mod lifecycle;
#[path = "browser_session_flow/limits.rs"]
mod limits;
#[path = "browser_session_flow/login_admission.rs"]
mod login_admission;
#[path = "browser_session_flow/observations.rs"]
mod observations;
#[allow(dead_code)]
#[path = "browser_management_tls/peer.rs"]
mod peer;
#[path = "browser_session_flow/refresh.rs"]
mod refresh;
#[allow(dead_code)]
#[path = "browser_management_tls/support.rs"]
mod support;

fn provider_config(pki: &support::Pki) -> OidcConfig {
    OidcConfig {
        issuer: "https://127.0.0.1:1/realms/apex".into(),
        client_id: "apex-browser".into(),
        client_secret: Zeroizing::new("fixture-browser-confidential-secret".into()),
        public_origin: "https://console.example".into(),
        provider_ca_pem: pki.trusted("ca.pem"),
        authorization_endpoint: "https://127.0.0.1:1/auth".into(),
        token_endpoint: "https://127.0.0.1:1/token".into(),
        jwks_uri: "https://127.0.0.1:1/jwks".into(),
        revocation_endpoint: "https://127.0.0.1:1/revoke".into(),
    }
}

#[test]
fn unauthenticated_http_is_closed_secret_free_and_never_calls_management() {
    let database = database::Database::new();
    let sessions = BrowserSessionStore::connect(&database.url).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let pki = support::Pki::require();
        let peer = peer::Peer::start(&pki, peer::Mode::Real).await;
        let resolver: Arc<dyn apex_control_plane_api::OperatorCredentialResolver> =
            Arc::new(support::resolver());
        let provider =
            Arc::new(OidcProvider::new(provider_config(&pki), Arc::clone(&resolver)).unwrap());
        let keys = Arc::new(
            TokenKeyring::new(vec![
                TokenKey::active("fixture", Zeroizing::new([8; 32])).unwrap(),
            ])
            .unwrap(),
        );
        let (telemetry, _export_owner) =
            apex_control_plane_api::browser::telemetry::BrowserTelemetry::with_writer(
                std::io::sink(),
            )
            .unwrap();
        let edge = BrowserEdge::new(
            BrowserConfig {
                session_max_age_secs: 28800,
                idle_timeout_secs: 900,
                max_in_flight: 16,
                request_timeout: Duration::from_secs(30),
            },
            BrowserDependencies {
                telemetry,
                sessions: sessions.clone(),
                keys,
                provider,
                management: support::connect(&pki, &peer.target, support::RPC_TIMEOUT).await,
                resolver,
                global_scope_catalog: Vec::new(),
            },
        )
        .expect("configured HTTP edge must construct");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let server = support::TestTask::spawn(async move {
            axum::serve(listener, edge.router())
                .with_graceful_shutdown(async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        for (method, path, expected) in [
            (reqwest::Method::GET, "/api/session", 401),
            (
                reqwest::Method::POST,
                "/api/apex/v1/McpProxyService/CreateProxy",
                403,
            ),
            (reqwest::Method::GET, "/not-an-api", 404),
            (reqwest::Method::POST, "/api/session", 405),
        ] {
            let response = client
                .request(method, format!("{origin}{path}"))
                .header("authorization", "Bearer browser-secret-canary")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected, "{path}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response.headers().contains_key("content-security-policy"));
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
            let body = response.text().await.unwrap();
            assert!(!body.contains("canary"));
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(body["error"]["code"].is_string());
        }
        assert_eq!(peer.state.rpc_calls(), 0);
        let _ = stop.send(());
        server.join().await;
        peer.shutdown().await;
        sessions.shutdown().await.unwrap();
    });
    let mut check = database.client();
    for table in ["apex_browser_sessions", "apex_browser_login_attempts"] {
        let count: i64 = check
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
    }
}
