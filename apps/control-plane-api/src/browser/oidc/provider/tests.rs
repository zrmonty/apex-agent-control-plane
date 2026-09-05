use super::*;
use crate::browser::oidc::{
    config::tests::{config, discovery},
    tokens::tests::{access_claims, material, resolver},
};
use crate::keycloak::tests::support::jwks;
use oauth2::{HttpRequest, HttpResponse};
use serde_json::json;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;

const NONCE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
struct Fixture {
    discovery: Vec<u8>,
    jwks: Vec<u8>,
    response: Vec<u8>,
    calls: Mutex<Vec<&'static str>>,
    block: AtomicBool,
    entered: AtomicUsize,
    release: Notify,
}
impl Fixture {
    fn new() -> Self {
        let tokens = material(access_claims(), "subject-123");
        Self {discovery:serde_json::to_vec(&discovery()).unwrap(),jwks:serde_json::to_vec(&jwks()).unwrap(),
            response:serde_json::to_vec(&json!({"access_token":tokens.access.as_str(),"refresh_token":tokens.refresh.as_str(),"id_token":tokens.id_token.as_ref().map(|id|id.as_str()),"token_type":"Bearer","expires_in":300,"refresh_expires_in":1800})).unwrap(),
            calls:Mutex::new(Vec::new()),block:AtomicBool::new(false),entered:AtomicUsize::new(0),release:Notify::new()}
    }
    fn core(self) -> ProviderCore<Self> {
        ProviderCore::new(Arc::new(config()), self, Arc::new(resolver())).unwrap()
    }
}
impl ProviderSource for Fixture {
    async fn discovery(&self) -> Result<Vec<u8>, BrowserError> {
        self.calls.lock().unwrap().push("discovery");
        Ok(self.discovery.clone())
    }
    async fn jwks(&self) -> Result<Vec<u8>, BrowserError> {
        self.calls.lock().unwrap().push("jwks");
        Ok(self.jwks.clone())
    }
}
impl ProviderHttp for Fixture {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BrowserError> {
        if request.uri().to_string() == config().revocation_endpoint {
            self.calls.lock().unwrap().push("revoke");
            return Ok(axum::http::Response::builder()
                .status(200)
                .body(Vec::new())
                .unwrap());
        }
        self.calls.lock().unwrap().push("token");
        self.entered.fetch_add(1, Ordering::SeqCst);
        if self.block.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        Ok(axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(self.response.clone())
            .unwrap())
    }
}
async fn login(core: &ProviderCore<Fixture>) -> Result<VerifiedProviderTokens, BrowserError> {
    core.exchange(
        TokenRequest::Code {
            code: "one-use-code",
            pkce: NONCE,
        },
        IdTokenExpectation::Login { nonce: NONCE },
    )
    .await
}

#[tokio::test]
async fn exchange_validates_discovery_then_jwks_before_single_token_request() {
    let core = Fixture::new().core();
    let result = login(&core).await.unwrap();
    assert_eq!(result.subject, "subject-123");
    assert_eq!(
        *core.http.calls.lock().unwrap(),
        ["discovery", "jwks", "token"]
    );
    assert!(!format!("{result:?}").contains("canary"));
}
#[tokio::test]
async fn invalid_metadata_never_reaches_later_endpoints() {
    let mut fixture = Fixture::new();
    let mut value = discovery();
    value["issuer"] = "https://untrusted.example".into();
    fixture.discovery = serde_json::to_vec(&value).unwrap();
    let core = fixture.core();
    assert!(login(&core).await.is_err());
    assert_eq!(*core.http.calls.lock().unwrap(), ["discovery"]);
    let mut fixture = Fixture::new();
    fixture.jwks = br#"{"keys":[]}"#.to_vec();
    let core = fixture.core();
    assert!(login(&core).await.is_err());
    assert_eq!(*core.http.calls.lock().unwrap(), ["discovery", "jwks"]);
}
#[tokio::test]
async fn authorization_only_uses_verified_discovery_and_independent_challenges() {
    let core = Fixture::new().core();
    let first = core.challenge().await.unwrap();
    let second = core.challenge().await.unwrap();
    assert_ne!(first.pkce.expose_secret(), second.pkce.expose_secret());
    assert_ne!(first.state.expose_secret(), second.state.expose_secret());
    assert_eq!(*core.http.calls.lock().unwrap(), ["discovery", "discovery"]);
    let mut fixture = Fixture::new();
    fixture.discovery = br#"{"issuer":"wrong"}"#.to_vec();
    assert!(fixture.core().challenge().await.is_err());
}
#[tokio::test]
async fn provider_exchange_uses_one_shared_ten_second_deadline_without_retry() {
    let fixture = Fixture::new();
    fixture.block.store(true, Ordering::SeqCst);
    let core = Arc::new(fixture.core());
    let owner = Arc::clone(&core);
    let task = tokio::spawn(async move { login(&owner).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while core.http.entered.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(11), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error, BrowserError::Unavailable);
    assert_eq!(
        *core.http.calls.lock().unwrap(),
        ["discovery", "jwks", "token"]
    );
    assert_eq!(core.slots.available_permits(), 8);
}
#[tokio::test]
async fn shared_exchange_admission_is_bounded_and_cancellation_releases_permits() {
    let fixture = Fixture::new();
    fixture.block.store(true, Ordering::SeqCst);
    let core = Arc::new(fixture.core());
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let owner = Arc::clone(&core);
        tasks.push(tokio::spawn(async move { login(&owner).await }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while core.http.entered.load(Ordering::SeqCst) != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(login(&core).await.unwrap_err(), BrowserError::RateLimited);
    assert_eq!(core.http.entered.load(Ordering::SeqCst), 8);
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    assert_eq!(core.slots.available_permits(), 8);
    core.http.block.store(false, Ordering::SeqCst);
    assert!(login(&core).await.is_ok());
    assert_eq!(core.http.entered.load(Ordering::SeqCst), 9);
}
#[tokio::test]
async fn revocation_is_fixed_single_attempt_and_consumes_no_login_documents() {
    let core = Fixture::new().core();
    core.revoke("refresh-canary").await.unwrap();
    assert_eq!(*core.http.calls.lock().unwrap(), ["revoke"]);
}

#[path = "timing_tests.rs"]
mod timing_tests;
