use super::*;
use crate::browser::oidc::config::tests::config;
use axum::http::{StatusCode, header};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};

const PKCE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
struct Capture {
    calls: Mutex<Vec<HttpRequest>>,
    status: StatusCode,
    body: Vec<u8>,
}
impl Capture {
    fn json(value: Value) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            status: StatusCode::OK,
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
}
impl ProviderHttp for Capture {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BrowserError> {
        self.calls.lock().unwrap().push(request);
        Ok(axum::http::Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(self.body.clone())
            .unwrap())
    }
}
fn response() -> Value {
    json!({"access_token":"access-secret-canary", "refresh_token":"refresh-secret-canary", "id_token":"id-secret-canary", "token_type":"Bearer", "expires_in":300, "refresh_expires_in":1800, "scope":"openid"})
}
fn form(request: &HttpRequest) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(request.body())
        .into_owned()
        .collect()
}

#[test]
fn authorization_uses_independent_os_secrets_and_only_code_s256_fixed_redirect() {
    let first = AuthorizationChallenge::new(&config()).unwrap();
    let second = AuthorizationChallenge::new(&config()).unwrap();
    let values = [
        first.state.expose_secret(),
        first.nonce.expose_secret(),
        first.pkce.expose_secret(),
        second.state.expose_secret(),
        second.nonce.expose_secret(),
        second.pkce.expose_secret(),
    ];
    let unique: std::collections::BTreeSet<_> = values.into_iter().collect();
    assert_eq!(unique.len(), 6);
    for value in unique {
        assert!(OpaqueToken::parse(value).is_ok());
        assert!(!format!("{first:?}").contains(value));
    }
    let params: BTreeMap<_, _> = first.url.query_pairs().into_owned().collect();
    assert_eq!(params.len(), 8);
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["scope"], "openid");
    assert_eq!(
        params["redirect_uri"],
        "https://console.example:8443/auth/callback"
    );
    assert_eq!(params["client_id"], "apex-browser");
    assert_eq!(params["state"], first.state.expose_secret());
    assert_eq!(params["nonce"], first.nonce.expose_secret());
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(
        params["code_challenge"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(first.pkce.expose_secret().as_bytes()))
    );
    assert!(!first.url.as_str().contains(first.pkce.expose_secret()));
    assert!(!first.url.as_str().contains(config().client_secret.as_str()));
    let mut target = first.url;
    target.set_query(None);
    assert_eq!(target.as_str(), config().authorization_endpoint);
}

#[tokio::test]
async fn code_exchange_keeps_client_secret_in_basic_and_pkce_in_server_request() {
    let client = ProtocolClient::new(&config()).unwrap();
    let http = Capture::json(response());
    let tokens = client
        .exchange(
            TokenRequest::Code {
                code: "one-use-code",
                pkce: PKCE,
            },
            &http,
        )
        .await
        .unwrap();
    assert_eq!(tokens.access.as_str(), "access-secret-canary");
    assert_eq!(tokens.refresh.as_str(), "refresh-secret-canary");
    assert_eq!(
        tokens.id_token.as_deref().unwrap().as_str(),
        "id-secret-canary"
    );
    assert_eq!(tokens.access_lifetime, 300);
    assert_eq!(tokens.refresh_lifetime, 1800);
    assert!(!format!("{tokens:?} {client:?}").contains("secret-canary"));
    let calls = http.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let request = &calls[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri().to_string(), config().token_endpoint);
    let expected = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            config().client_id,
            config().client_secret.as_str()
        ))
    );
    assert_eq!(request.headers()[header::AUTHORIZATION], expected);
    assert_eq!(
        request.headers()[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    let params = form(request);
    assert_eq!(params.len(), 4);
    assert_eq!(params["grant_type"], "authorization_code");
    assert_eq!(params["code"], "one-use-code");
    assert_eq!(params["code_verifier"], PKCE);
    assert_eq!(
        params["redirect_uri"],
        "https://console.example:8443/auth/callback"
    );
}

#[tokio::test]
async fn invalid_inputs_do_not_reach_provider_and_errors_do_not_leak() {
    let client = ProtocolClient::new(&config()).unwrap();
    let http = Capture::json(response());
    for code in ["", "bad code", "\r\nsecret-canary"] {
        assert!(
            client
                .exchange(TokenRequest::Code { code, pkce: PKCE }, &http)
                .await
                .is_err()
        );
    }
    for pkce in [
        "",
        "plain-verifier",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF",
    ] {
        assert!(
            client
                .exchange(TokenRequest::Code { code: "code", pkce }, &http)
                .await
                .is_err()
        );
    }
    for token in ["", "bad refresh", "\nrefresh"] {
        assert!(
            client
                .exchange(TokenRequest::Refresh { token }, &http)
                .await
                .is_err()
        );
        assert!(client.revoke(token, &http).await.is_err());
    }
    assert!(http.calls.lock().unwrap().is_empty());
    let mut failure = Capture::json(
        json!({"error":"invalid_grant","error_description":"provider-secret-canary"}),
    );
    failure.status = StatusCode::BAD_REQUEST;
    let error = client
        .exchange(
            TokenRequest::Code {
                code: "code",
                pkce: PKCE,
            },
            &failure,
        )
        .await
        .unwrap_err();
    assert_eq!(error, BrowserError::Unauthenticated);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert_eq!(failure.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn refresh_requires_rotation_but_allows_missing_id_token() {
    let client = ProtocolClient::new(&config()).unwrap();
    let mut value = response();
    value.as_object_mut().unwrap().remove("id_token");
    let http = Capture::json(value);
    let tokens = client
        .exchange(
            TokenRequest::Refresh {
                token: "old-refresh",
            },
            &http,
        )
        .await
        .unwrap();
    assert!(tokens.id_token.is_none());
    {
        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let params = form(&calls[0]);
        assert_eq!(params.len(), 2);
        assert_eq!(params["grant_type"], "refresh_token");
        assert_eq!(params["refresh_token"], "old-refresh");
    }
    let reused = Capture::json(response());
    assert!(
        client
            .exchange(
                TokenRequest::Refresh {
                    token: "refresh-secret-canary"
                },
                &reused
            )
            .await
            .is_err()
    );
    assert_eq!(reused.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn token_profile_requires_bounded_tokens_lifetimes_and_bearer() {
    let client = ProtocolClient::new(&config()).unwrap();
    assert!(
        client
            .exchange(
                TokenRequest::Code {
                    code: "code",
                    pkce: PKCE
                },
                &Capture::json(response())
            )
            .await
            .is_ok()
    );
    for (field, bad) in [
        ("access_token", json!("")),
        ("access_token", json!("x".repeat(4097))),
        ("refresh_token", json!(null)),
        ("refresh_token", json!("bad token")),
        ("id_token", json!(null)),
        ("id_token", json!("x".repeat(16385))),
        ("token_type", json!("MAC")),
        ("expires_in", json!(0)),
        ("expires_in", json!(3601)),
        ("expires_in", json!(null)),
        ("refresh_expires_in", json!(0)),
        ("refresh_expires_in", json!(86401)),
        ("refresh_expires_in", json!(null)),
        ("scope", json!("openid offline_access")),
    ] {
        let mut value = response();
        value[field] = bad;
        let http = Capture::json(value);
        assert!(
            client
                .exchange(
                    TokenRequest::Code {
                        code: "code",
                        pkce: PKCE
                    },
                    &http
                )
                .await
                .is_err(),
            "{field}"
        );
        assert_eq!(http.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn revoke_is_single_attempt_server_side_form_with_no_redirect() {
    let client = ProtocolClient::new(&config()).unwrap();
    let mut http = Capture::json(json!({}));
    http.body.clear();
    client.revoke("refresh-secret-canary", &http).await.unwrap();
    let calls = http.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].uri().to_string(), config().revocation_endpoint);
    let params = form(&calls[0]);
    assert_eq!(params.len(), 2);
    assert_eq!(params["token"], "refresh-secret-canary");
    assert_eq!(params["token_type_hint"], "refresh_token");
    assert!(calls[0].headers().contains_key(header::AUTHORIZATION));
}

#[tokio::test]
async fn refresh_explicit_null_id_token_is_malformed_not_an_absent_token() {
    let client = ProtocolClient::new(&config()).unwrap();
    let mut absent = response();
    absent.as_object_mut().unwrap().remove("id_token");
    let allowed = Capture::json(absent);
    assert!(
        client
            .exchange(
                TokenRequest::Refresh {
                    token: "old-refresh"
                },
                &allowed
            )
            .await
            .is_ok()
    );
    assert_eq!(allowed.calls.lock().unwrap().len(), 1);

    let mut malformed = response();
    malformed["id_token"] = Value::Null;
    let rejected = Capture::json(malformed);
    let result = client
        .exchange(
            TokenRequest::Refresh {
                token: "old-refresh",
            },
            &rejected,
        )
        .await;
    assert!(
        result.is_err(),
        "present null must not select the optional no-ID refresh path"
    );
    assert_eq!(rejected.calls.lock().unwrap().len(), 1);
}
