//! Lab-only HTTP user agent for the real Keycloak HTML login form. It follows
//! only explicitly checked locations and never exports bodies or credentials.
use super::support;
use apex_control_plane_api::browser::security::OpaqueToken;
use reqwest::{Client, Response};
use std::{collections::BTreeMap, time::Duration};
use url::Url;
use zeroize::Zeroizing;

pub struct Browser {
    client: Client,
}
pub struct Session {
    pub cookie: String,
    pub login_cookie: String,
    pub callback: String,
}
impl Browser {
    pub fn new(pki: &support::Pki) -> Self {
        let certificate = reqwest::Certificate::from_pem(&pki.trusted("ca.pem")).unwrap();
        let client = Client::builder()
            .tls_certs_only([certificate])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        Self { client }
    }
    pub async fn login(&self, edge: &str, issuer: &str) -> Session {
        let response = self
            .client
            .get(format!("{edge}/auth/login"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            302,
            "configured login route must issue a provider challenge"
        );
        let login_cookie = application_cookie(&response, "__Host-apex_login");
        let authorization = location(&response);
        let authorization = Url::parse(&authorization).unwrap();
        assert_provider_path(&authorization, issuer, "/protocol/openid-connect/auth");
        let params: BTreeMap<_, _> = authorization
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("apex-browser")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://console.example/auth/callback")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(params.get("scope").map(String::as_str), Some("openid"));
        for key in ["state", "nonce", "code_challenge"] {
            assert!(OpaqueToken::parse(params.get(key).unwrap()).is_ok());
        }
        assert!(!params.contains_key("client_secret"));
        assert!(!params.contains_key("code_verifier"));
        assert_ne!(params["state"], params["nonce"]);

        let response = self.client.get(authorization).send().await.unwrap();
        assert_eq!(response.status(), 200, "real Keycloak login form must load");
        let cookies = provider_cookies(&response);
        assert!(
            response
                .content_length()
                .is_none_or(|length| length <= 256 * 1024)
        );
        let body = response.bytes().await.unwrap();
        assert!(body.len() <= 256 * 1024);
        let html = std::str::from_utf8(&body).unwrap();
        let form = html
            .split("id=\"kc-form-login\"")
            .nth(1)
            .expect("expected Keycloak login form");
        let form = form.split('>').next().unwrap();
        let action = form
            .split("action=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .replace("&amp;", "&");
        let action = Url::parse(&action).unwrap();
        assert_provider_path(&action, issuer, "/login-actions/authenticate");
        let (username, password) = lab_credentials();
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("username", username.as_str()),
                    ("password", password.as_str()),
                    ("credentialId", ""),
                ])
                .finish(),
        );
        let response = self
            .client
            .post(action)
            .header("cookie", cookies)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            302,
            "real Keycloak must complete the lab human login"
        );
        let callback = Url::parse(&location(&response)).unwrap();
        assert_eq!(
            callback.origin().ascii_serialization(),
            "https://console.example"
        );
        assert_eq!(callback.path(), "/auth/callback");
        assert!(callback.fragment().is_none());
        let result: BTreeMap<_, _> = callback
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert!(result.contains_key("code"));
        assert!(!result.contains_key("error"));
        assert!(result.get("state") == params.get("state"));
        // Deliberate test mapping to the confined internal hop; actual external
        // browser HTTPS termination and cookie-jar policy remain a release test.
        let callback = format!("{edge}/auth/callback?{}", callback.query().unwrap());
        let response = self
            .client
            .get(&callback)
            .header("cookie", &login_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            303,
            "verified callback must create a durable opaque session"
        );
        assert_eq!(location(&response), "/");
        let cookie = application_cookie(&response, "__Host-apex_session");
        Session {
            cookie,
            login_cookie,
            callback,
        }
    }
}

fn location(response: &Response) -> String {
    let values: Vec<_> = response.headers().get_all("location").iter().collect();
    assert_eq!(values.len(), 1);
    values[0].to_str().unwrap().to_owned()
}
fn application_cookie(response: &Response, name: &str) -> String {
    let prefix = format!("{name}=");
    let values: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .filter(|value| value.starts_with(&prefix))
        .collect();
    assert_eq!(values.len(), 1);
    let value = values[0];
    for required in ["; Secure", "; HttpOnly", "; SameSite=Lax", "; Path=/"] {
        assert!(value.contains(required));
    }
    assert!(!value.contains("Domain="));
    let cookie = value.split(';').next().unwrap();
    assert!(OpaqueToken::parse(cookie.strip_prefix(&prefix).unwrap()).is_ok());
    cookie.to_owned()
}
fn provider_cookies(response: &Response) -> String {
    let values: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(!values.is_empty() && values.len() <= 16);
    values
        .iter()
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
fn assert_provider_path(value: &Url, issuer: &str, suffix: &str) {
    let configured = Url::parse(issuer).unwrap();
    assert_eq!(value.origin(), configured.origin());
    assert_eq!(value.path(), format!("{}{suffix}", configured.path()));
    assert!(
        value.username().is_empty() && value.password().is_none() && value.fragment().is_none()
    );
}
fn lab_credentials() -> (String, Zeroizing<String>) {
    let realm: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../deploy/compose/gateway-ref/keycloak/apex-realm.json"
    ))
    .unwrap();
    let users: Vec<_> = realm["users"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|user| {
            user["enabled"] == true
                && !user["username"]
                    .as_str()
                    .unwrap()
                    .starts_with("service-account-")
                && user["credentials"].as_array().is_some_and(|credentials| {
                    credentials.iter().any(|value| value["type"] == "password")
                })
        })
        .collect();
    assert_eq!(
        users.len(),
        1,
        "fixture must have one unambiguous lab human"
    );
    let user = users[0];
    let credential = user["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["type"] == "password")
        .unwrap();
    (
        user["username"].as_str().unwrap().into(),
        Zeroizing::new(credential["value"].as_str().unwrap().into()),
    )
}
