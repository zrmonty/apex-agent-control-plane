use super::super::protocol::{ProtocolClient, ProviderHttp, TokenRequest};
use super::{BoundedProviderHttp, test_peer::*};
use crate::browser::errors::BrowserError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oauth2::http::{HeaderValue, Method};

#[test]
fn prepared_post_marks_authorization_sensitive_and_redacts_request_debug() {
    // Header sensitivity is local metadata, not visible on the TLS wire. Inspect
    // the exact request-building seam that send will use, not a second client.
    let config = fixture_config("127.0.0.1:18450".parse().unwrap());
    let http = BoundedProviderHttp::new(&config).unwrap();
    let request = http.prepare_post(post(&config.token_endpoint)).unwrap();
    let authorization = &request.headers()["authorization"];
    assert!(authorization.is_sensitive());
    let debug = format!("{request:?}");
    assert!(!debug.contains(authorization.to_str().unwrap()));
    assert!(!debug.contains(config.client_secret.as_str()));
}

#[tokio::test]
async fn discovery_and_jwks_use_only_fixed_https_get_paths_without_credentials() {
    let peer = Peer::start(Vec::new()).await;
    let http = BoundedProviderHttp::new(&peer.config()).unwrap();
    assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);
    assert_eq!(bounded(http.jwks()).await.unwrap(), JSON);
    let calls = peer.requests();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].path,
        "/realms/apex/.well-known/openid-configuration"
    );
    assert_eq!(calls[1].path, "/realms/apex/certs");
    for call in calls {
        assert_eq!(call.method, "GET");
        assert!(call.body.is_empty());
        assert_eq!(call.header("accept"), Some("application/json"));
        for name in [
            "authorization",
            "cookie",
            "origin",
            "proxy-authorization",
            "accept-encoding",
        ] {
            assert!(call.header(name).is_none(), "GET leaked {name}");
        }
    }
}

#[tokio::test]
async fn token_and_revocation_posts_preserve_form_and_confidential_client_basic_auth() {
    let peer = Peer::start(vec![
        Reply::json(200, JSON),
        Reply::wire(response(200, None, b"")),
    ])
    .await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    for uri in [&config.token_endpoint, &config.revocation_endpoint] {
        assert_eq!(bounded(http.send(post(uri))).await.unwrap().status(), 200);
    }
    let calls = peer.requests();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].path, "/realms/apex/token");
    assert_eq!(calls[1].path, "/realms/apex/revoke");
    for call in calls {
        assert_eq!(call.method, "POST");
        assert_eq!(call.body, FORM);
        assert_eq!(
            call.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(call.header("accept"), Some("application/json"));
        let basic = call
            .header("authorization")
            .unwrap()
            .strip_prefix("Basic ")
            .unwrap();
        assert_eq!(
            STANDARD.decode(basic).unwrap(),
            b"apex-browser:fixture-confidential-client-secret"
        );
    }
}

#[tokio::test]
async fn actual_oauth_library_requests_work_with_rfc6749_encoded_basic_credentials() {
    let body = br#"{"access_token":"access-canary","refresh_token":"rotated-canary","token_type":"Bearer","expires_in":300,"refresh_expires_in":1800,"id_token":"id-canary"}"#;
    let peer = Peer::start(vec![
        Reply::json(200, body),
        Reply::json(200, body),
        Reply::wire(response(200, None, b"")),
    ])
    .await;
    let mut config = peer.config();
    config.client_id = "client:+@".into();
    config.client_secret = "fixture-secret:+@".to_owned().into();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let protocol = ProtocolClient::new(&config).unwrap();
    let tokens = bounded(protocol.exchange(
        TokenRequest::Code {
            code: "code+&=%",
            pkce: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        },
        &http,
    ))
    .await
    .unwrap();
    assert_eq!(tokens.access.as_str(), "access-canary");
    bounded(protocol.exchange(
        TokenRequest::Refresh {
            token: "refresh+&=%",
        },
        &http,
    ))
    .await
    .unwrap();
    bounded(protocol.revoke("revoke+&=%", &http)).await.unwrap();
    let calls = peer.requests();
    assert_eq!(calls.len(), 3);
    assert_form(
        &calls[0],
        "/realms/apex/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", "code+&=%"),
            (
                "code_verifier",
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            ),
            ("redirect_uri", "https://console.example:8443/auth/callback"),
        ],
    );
    assert_form(
        &calls[1],
        "/realms/apex/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", "refresh+&=%"),
        ],
    );
    assert_form(
        &calls[2],
        "/realms/apex/revoke",
        &[
            ("token", "revoke+&=%"),
            ("token_type_hint", "refresh_token"),
        ],
    );
    for call in calls {
        let basic = call
            .header("authorization")
            .unwrap()
            .strip_prefix("Basic ")
            .unwrap();
        assert_eq!(
            STANDARD.decode(basic).unwrap(),
            b"client%3A%2B%40:fixture-secret%3A%2B%40"
        );
        assert!(!String::from_utf8_lossy(&call.body).contains("fixture-secret"));
    }
}

fn assert_form(call: &Recorded, path: &str, expected: &[(&str, &str)]) {
    assert_eq!(call.method, "POST");
    assert_eq!(call.path, path);
    assert_eq!(
        call.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let mut actual: Vec<_> = url::form_urlencoded::parse(&call.body)
        .into_owned()
        .collect();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    actual.sort();
    expected.sort();
    // Full tuple equality rejects duplicates, extra credentials, dropped fields,
    // and a second decoding pass without depending on irrelevant field order.
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn wrong_destination_path_query_scheme_or_method_is_rejected_before_any_io() {
    let peer = Peer::start(Vec::new()).await;
    let trap = Peer::start(Vec::new()).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let bad = [
        format!("https://{}/realms/apex/token", trap.address),
        format!("http://{}/realms/apex/token", peer.address),
        format!("{}/extra", config.token_endpoint),
        format!("{}?next=canary", config.token_endpoint),
        format!("https://{}/realms/apex/%74oken", peer.address),
        format!("https://{}/realms/apex/a/../token", peer.address),
        config.authorization_endpoint.clone(),
        config.jwks_uri.clone(),
    ];
    for uri in bad {
        assert!(
            bounded(http.send(post(&uri))).await.is_err(),
            "accepted {uri}"
        );
    }
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::HEAD] {
        let mut request = post(&config.token_endpoint);
        *request.method_mut() = method;
        assert!(bounded(http.send(request)).await.is_err());
    }
    assert_eq!(
        peer.connections(),
        0,
        "invalid requests reached the configured host"
    );
    assert_eq!(trap.connections(), 0, "SSRF input reached the foreign host");
}

#[tokio::test]
async fn request_body_accepts_16384_bytes_but_rejects_16385_before_io() {
    let peer = Peer::start(Vec::new()).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let mut accepted = post(&config.token_endpoint);
    *accepted.body_mut() = format!("x={}", "a".repeat(16382)).into_bytes();
    bounded(http.send(accepted)).await.unwrap();
    assert_eq!(peer.requests()[0].body.len(), 16384);
    let before = peer.connections();
    let mut rejected = post(&config.token_endpoint);
    *rejected.body_mut() = format!("x={}", "a".repeat(16383)).into_bytes();
    assert!(bounded(http.send(rejected)).await.is_err());
    assert_eq!(peer.connections(), before);
    assert_eq!(peer.requests().len(), 1);
}

#[tokio::test]
async fn absent_wrong_or_duplicate_expected_headers_fail_before_io() {
    let peer = Peer::start(Vec::new()).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    for name in ["authorization", "accept", "content-type"] {
        let mut absent = post(&config.token_endpoint);
        absent.headers_mut().remove(name);
        assert!(bounded(http.send(absent)).await.is_err(), "missing {name}");
        let mut duplicate = post(&config.token_endpoint);
        let value = duplicate.headers()[name].clone();
        duplicate.headers_mut().append(name, value);
        assert!(
            bounded(http.send(duplicate)).await.is_err(),
            "duplicate {name}"
        );
    }
    for (name, value) in [
        ("authorization", "Bearer browser-token-canary"),
        ("authorization", "Basic d3Jvbmc6Y3JlZGVudGlhbHM="),
        ("accept", "text/html"),
        ("content-type", "application/json"),
        (
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8",
        ),
    ] {
        let mut request = post(&config.token_endpoint);
        request
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
        assert!(bounded(http.send(request)).await.is_err(), "wrong {name}");
    }
    assert_eq!(peer.connections(), 0);
}

#[tokio::test]
async fn untrusted_header_values_cannot_be_forwarded_to_provider() {
    let peer = Peer::start(Vec::new()).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    // A clean positive control prevents fail-all transport from proving isolation.
    bounded(http.send(post(&config.token_endpoint)))
        .await
        .unwrap();
    let before = peer.connections();
    let mut request = post(&config.token_endpoint);
    for name in [
        "cookie",
        "origin",
        "referer",
        "forwarded",
        "x-forwarded-host",
        "x-operator-id",
        "proxy-authorization",
        "x-browser-canary",
        "host",
    ] {
        request
            .headers_mut()
            .insert(name, HeaderValue::from_static("browser-secret-canary"));
    }
    // Rejecting the malformed envelope or rebuilding only trusted headers is safe.
    // It must never forward a browser-controlled value, including Host.
    match bounded(http.send(request)).await {
        Err(_) => assert_eq!(peer.connections(), before),
        Ok(_) => {
            let calls = peer.requests();
            assert_eq!(calls.len(), 2);
            let call = &calls[1];
            for (name, value) in &call.headers {
                assert!(!value.contains("browser-secret-canary"), "leaked {name}");
                assert!(
                    [
                        "authorization",
                        "accept",
                        "content-type",
                        "content-length",
                        "host",
                        "connection"
                    ]
                    .contains(&name.as_str()),
                    "unexpected forwarded {name}"
                );
            }
        }
    }
}

#[test]
fn constructor_rejects_invalid_deployment_config_and_unparseable_ca() {
    let address = "127.0.0.1:18450".parse().unwrap();
    let valid = fixture_config(address);
    assert!(BoundedProviderHttp::new(&valid).is_ok());
    for field in 0..6 {
        let mut config = fixture_config(address);
        match field {
            0 => config.issuer = "http://127.0.0.1/realm".into(),
            1 => config.token_endpoint.push_str("?attacker=canary"),
            2 => config.revocation_endpoint = "https://user:secret@127.0.0.1/revoke".into(),
            3 => config.client_secret.clear(),
            4 => config.provider_ca_pem = b"not a certificate: secret-canary".to_vec(),
            _ => config.provider_ca_pem.clear(),
        }
        let error = BoundedProviderHttp::new(&config).expect_err("invalid config was accepted");
        assert_eq!(error, BrowserError::Unavailable);
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
}
