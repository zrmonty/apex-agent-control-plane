use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apex_control_plane_api::{KeycloakConfig, KeycloakOperatorCredentialResolver};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

pub(crate) fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_KEYCLOAK").ok().as_deref() == Some("1")
}

/// Where the host reaches Keycloak. Distinct from [`ISSUER`] on purpose: the
/// issuer is fixed to the in-network address by `KC_HOSTNAME`, so tokens
/// minted through the published port still carry the issuer the gateway
/// container is configured with. That split is exactly why the resolver does
/// **not** require the JWKS URL to share an origin with the issuer -- see
/// `KeycloakConfig::validate`.
pub(crate) fn keycloak_base() -> String {
    std::env::var("APEX_CONTROL_LIVE_KEYCLOAK_BASE")
        .unwrap_or_else(|_| "https://localhost:18450".to_owned())
}

pub(crate) const ISSUER: &str = "https://keycloak:8443/realms/apex";
pub(crate) const OTHER_ISSUER: &str = "https://keycloak:8443/realms/other";
pub(crate) const AUDIENCE: &str = "apex-control-gateway";

pub(crate) fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets-host")
}

pub(crate) fn require_secret(root: &Path, name: &str) -> Vec<u8> {
    let path = root.join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS fixture {name} under {}; run generate_pki.py",
        root.display()
    );
    std::fs::read(&path).expect("fixture must be readable")
}

pub(crate) fn lab_ca() -> Vec<u8> {
    require_secret(&secrets_dir(), "ca.pem")
}

/// Mints a real access token through Keycloak's `client_credentials` grant.
///
/// Runs the whole blocking request on a plain OS thread. `reqwest::blocking`
/// owns an internal runtime and refuses to be constructed inside an async one,
/// and this helper is called from both `#[test]` and `#[tokio::test]`
/// functions -- the same hazard that keeps `startup::service::run`
/// synchronous.
pub(crate) fn mint_token(realm: &str, client_id: &str, client_secret: &str) -> String {
    let url = format!(
        "{}/realms/{realm}/protocol/openid-connect/token",
        keycloak_base()
    );
    let client_id = client_id.to_owned();
    let client_secret = client_secret.to_owned();
    let ca = lab_ca();
    std::thread::spawn(move || {
        apex_control_plane_api::install_rustls_provider();
        let client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([
                reqwest::Certificate::from_pem(&ca).expect("lab CA must parse"),
            ])
            .timeout(Duration::from_secs(20))
            .build()
            .expect("token client must build");
        // Keycloak binds its listener only after realm import finishes, but a
        // healthcheck race is still cheaper to absorb here than to debug in a
        // CI log.
        // Hand-built form body: `reqwest` is depended on without its default
        // features (see Cargo.toml), so `RequestBuilder::form` and
        // `Response::json` are not compiled in. The fixture client ids and
        // secrets are plain ASCII with no characters needing escaping, which
        // is asserted rather than assumed.
        for value in [client_id.as_str(), client_secret.as_str()] {
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                "fixture credentials must need no form escaping: {value:?}"
            );
        }
        let body = format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}"
        );
        let mut last = String::new();
        for _ in 0..30 {
            match client
                .post(&url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body.clone())
                .send()
            {
                Ok(response) if response.status().is_success() => {
                    let text = response.text().expect("token response body");
                    let body: serde_json::Value =
                        serde_json::from_str(&text).expect("token response must be JSON");
                    return body["access_token"]
                        .as_str()
                        .expect("token response must carry access_token")
                        .to_owned();
                }
                Ok(response) => {
                    last = format!("HTTP {}", response.status());
                }
                Err(error) => last = error.to_string(),
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        panic!("could not mint a token from {url}: {last}");
    })
    .join()
    .expect("token thread must not panic")
}

pub(crate) fn scoped_token() -> String {
    mint_token("apex", AUDIENCE, "apex-control-lab-client-secret")
}

/// The verifier as a deployment would configure it, except that the JWKS is
/// fetched through the host-published port.
pub(crate) fn resolver(configure: impl FnOnce(&mut KeycloakConfig)) -> KeycloakOperatorCredentialResolver {
    let mut config = KeycloakConfig {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: format!(
            "{}/realms/apex/protocol/openid-connect/certs",
            keycloak_base()
        ),
        jwks_ca_pem: lab_ca(),
        jwks_refresh: Duration::from_secs(30),
        jwks_max_age: Duration::from_secs(300),
        scope_claim: "apex_control_scopes".to_owned(),
        role_claim: "realm_access.roles".to_owned(),
        global_role: None,
        global_subjects: BTreeSet::new(),
        max_token_lifetime: Duration::from_secs(3600),
        expected_typ: Some("Bearer".to_owned()),
    };
    configure(&mut config);
    let resolver = KeycloakOperatorCredentialResolver::start(config)
        .expect("the resolver must build against the live realm");
    assert!(
        resolver.keys_are_fresh(),
        "the resolver must have fetched the live JWKS during start()"
    );
    resolver
}

pub(crate) fn claims_of(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&B64URL.decode(payload).expect("payload must be base64url"))
        .expect("payload must be JSON")
}

pub(crate) fn subject_of(token: &str) -> String {
    claims_of(token)["sub"]
        .as_str()
        .expect("a Keycloak access token carries sub")
        .to_owned()
}

/// Reassembles a token with a chosen header and signature over the *real*
/// payload Keycloak issued, for the shapes no signing library will produce.
pub(crate) fn forge(header: serde_json::Value, token: &str, signature: &str) -> String {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    format!(
        "{}.{payload}.{signature}",
        B64URL.encode(serde_json::to_vec(&header).expect("header"))
    )
}

pub(crate) fn kid_of(token: &str) -> String {
    let header = token.split('.').next().expect("a JWT has three parts");
    let header: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(header).expect("header must be base64url"))
            .expect("header must be JSON");
    header["kid"]
        .as_str()
        .expect("Keycloak always sets kid")
        .to_owned()
}
