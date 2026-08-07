//! Live operator-credential tests against a **real Keycloak**.
//!
//! Enabled only when `APEX_CONTROL_LIVE_KEYCLOAK=1`, so offline unit CI stays
//! green. Start the stack with
//! `deploy/compose/compose.gateway-ref.yaml -f compose.control-keycloak.yaml`.
//!
//! `src/keycloak/tests.rs` already covers every rejection offline against
//! locally minted tokens and a fixture JWKS. This file exists because that is
//! not the same claim: a hand-rolled mock and a hand-rolled verifier can agree
//! with each other while both disagree with the identity provider. What only a
//! real Keycloak can establish is that the verifier works against the shape
//! Keycloak actually emits -- `aud` as an *array* carrying `account` alongside
//! the audience we asked for, `typ` as a payload claim rather than a header
//! one, a `kid` that is a base64url thumbprint, roles nested under
//! `realm_access.roles`, and a JWKS that publishes an `RSA-OAEP`/`use: enc`
//! key next to the signing key.
//!
//! The last of those is the one worth stating plainly: Keycloak's JWKS
//! contains a key this verifier must never verify a signature with, and it is
//! there by default, in every realm, with no misconfiguration required.
//!
//! Two halves:
//!
//!  1. `KeycloakOperatorCredentialResolver` driven directly, fetching the real
//!     JWKS over HTTPS and verifying real tokens. This is where the negative
//!     cases live, because minting them requires driving Keycloak's own
//!     clients (a one-second token lifespan, a second realm, an over-broad
//!     claim mapper).
//!  2. The **deployed** path: a `control-plane-api` container configured with
//!     `APEX_CONTROL_KEYCLOAK_ISSUER` and nothing else, accepting a real
//!     Keycloak token over mTLS. Without this, `build_operator_resolver`'s
//!     third branch would be untested in the only place it actually runs --
//!     the class of gap that has already reached `master` in this repository
//!     twice (an unwired fanout worker, an inert `postgres` feature).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apex_control_plane_api::{
    CommandErrorCode, KeycloakConfig, KeycloakOperatorCredentialResolver,
    OperatorCredentialResolver, proto,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_KEYCLOAK").ok().as_deref() == Some("1")
}

/// Where the host reaches Keycloak. Distinct from [`ISSUER`] on purpose: the
/// issuer is fixed to the in-network address by `KC_HOSTNAME`, so tokens
/// minted through the published port still carry the issuer the gateway
/// container is configured with. That split is exactly why the resolver does
/// **not** require the JWKS URL to share an origin with the issuer -- see
/// `KeycloakConfig::validate`.
fn keycloak_base() -> String {
    std::env::var("APEX_CONTROL_LIVE_KEYCLOAK_BASE")
        .unwrap_or_else(|_| "https://localhost:18450".to_owned())
}

const ISSUER: &str = "https://keycloak:8443/realms/apex";
const OTHER_ISSUER: &str = "https://keycloak:8443/realms/other";
const AUDIENCE: &str = "apex-control-gateway";

fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets-host")
}

fn require_secret(root: &Path, name: &str) -> Vec<u8> {
    let path = root.join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS fixture {name} under {}; run generate_pki.py",
        root.display()
    );
    std::fs::read(&path).expect("fixture must be readable")
}

fn lab_ca() -> Vec<u8> {
    require_secret(&secrets_dir(), "ca.pem")
}

/// Mints a real access token through Keycloak's `client_credentials` grant.
///
/// Runs the whole blocking request on a plain OS thread. `reqwest::blocking`
/// owns an internal runtime and refuses to be constructed inside an async one,
/// and this helper is called from both `#[test]` and `#[tokio::test]`
/// functions -- the same hazard that keeps `startup::service::run`
/// synchronous.
fn mint_token(realm: &str, client_id: &str, client_secret: &str) -> String {
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

fn scoped_token() -> String {
    mint_token("apex", AUDIENCE, "apex-control-lab-client-secret")
}

/// The verifier as a deployment would configure it, except that the JWKS is
/// fetched through the host-published port.
fn resolver(configure: impl FnOnce(&mut KeycloakConfig)) -> KeycloakOperatorCredentialResolver {
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

fn claims_of(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&B64URL.decode(payload).expect("payload must be base64url"))
        .expect("payload must be JSON")
}

fn subject_of(token: &str) -> String {
    claims_of(token)["sub"]
        .as_str()
        .expect("a Keycloak access token carries sub")
        .to_owned()
}

/// Reassembles a token with a chosen header and signature over the *real*
/// payload Keycloak issued, for the shapes no signing library will produce.
fn forge(header: serde_json::Value, token: &str, signature: &str) -> String {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    format!(
        "{}.{payload}.{signature}",
        B64URL.encode(serde_json::to_vec(&header).expect("header"))
    )
}

fn kid_of(token: &str) -> String {
    let header = token.split('.').next().expect("a JWT has three parts");
    let header: serde_json::Value =
        serde_json::from_slice(&B64URL.decode(header).expect("header must be base64url"))
            .expect("header must be JSON");
    header["kid"]
        .as_str()
        .expect("Keycloak always sets kid")
        .to_owned()
}

// ---------------------------------------------------------------------------
// Half one: the verifier against the live realm.
// ---------------------------------------------------------------------------

#[test]
fn a_real_keycloak_token_maps_to_exactly_the_scopes_its_claim_carries() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let caller = resolver(|_| {})
        .resolve(&token)
        .expect("a genuine, in-date Keycloak token must verify");
    assert_eq!(
        caller.subject(),
        format!("operator:keycloak:{}", subject_of(&token))
    );
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("acme", "staging"));
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));
}

/// Keycloak's JWKS publishes an `RSA-OAEP` / `use: enc` key next to the
/// signing key, in every realm, by default. A verifier that selected a key by
/// `kid` without checking what the key is *for* would be one realm-config
/// change away from verifying signatures with encryption material.
#[test]
fn the_live_jwks_really_does_publish_an_encryption_key_alongside_the_signing_key() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let ca = lab_ca();
    let url = format!(
        "{}/realms/apex/protocol/openid-connect/certs",
        keycloak_base()
    );
    let body = std::thread::spawn(move || {
        apex_control_plane_api::install_rustls_provider();
        reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(&ca).expect("lab CA")])
            .timeout(Duration::from_secs(20))
            .build()
            .expect("client")
            .get(&url)
            .send()
            .expect("JWKS must be reachable")
            .text()
            .expect("JWKS body")
    })
    .join()
    .expect("jwks thread");
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("JWKS must be JSON");
    let keys = jwks["keys"].as_array().expect("JWKS carries keys");
    assert!(
        keys.iter().any(|key| key["use"] == "enc"),
        "expected the realm to publish an encryption key; if Keycloak stops doing that, the JWK_NOT_FOR_SIGNATURES guard is still correct but this test no longer proves it: {body}"
    );
    assert!(keys.iter().any(|key| key["use"] == "sig"));
}

#[test]
fn a_genuinely_expired_keycloak_token_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Minted by a client whose access.token.lifespan is one second, so this is
    // a real Keycloak signature over a real payload that has simply aged out
    // -- not a hand-edited `exp`.
    let token = mint_token(
        "apex",
        "apex-control-shortlived",
        "apex-control-lab-shortlived-secret",
    );
    let resolver = resolver(|_| {});
    // Past the one-second lifespan *and* past the 30s clock-skew leeway.
    std::thread::sleep(Duration::from_secs(35));
    let error = resolver.resolve(&token).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Unauthenticated);
}

#[test]
fn a_keycloak_token_that_is_simply_not_short_lived_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Twelve-hour lifespan, real signature, in date. Nothing about the
    // signature or the registered claims is wrong; it is refused purely
    // because "short-lived" is enforced rather than assumed.
    let token = mint_token(
        "apex",
        "apex-control-longlived",
        "apex-control-lab-longlived-secret",
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
    // ... and it verifies once the deployment's ceiling actually permits that
    // lifetime, which is what proves the refusal above was the ceiling and not
    // something else about the token.
    let permissive = resolver(|config: &mut KeycloakConfig| {
        config.max_token_lifetime = Duration::from_secs(86_400)
    });
    assert!(permissive.resolve(&token).is_ok());
}

#[test]
fn a_token_from_another_realm_on_the_same_keycloak_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Same client id, same audience mapper, different realm -- so the only
    // things that differ are the issuer and the signing key.
    let token = mint_token("other", AUDIENCE, "apex-control-lab-other-realm-secret");
    assert_eq!(
        claims_of(&token)["iss"].as_str(),
        Some(OTHER_ISSUER),
        "the fixture realm must actually be a different issuer"
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn a_real_token_with_a_tampered_signature_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let resolver = resolver(|_| {});
    assert!(resolver.resolve(&token).is_ok(), "control: unmodified");

    let (message, signature) = token.rsplit_once('.').expect("a JWT has three parts");
    let mut bytes = B64URL.decode(signature).expect("signature must be base64url");
    bytes[0] ^= 0x01;
    let tampered = format!("{message}.{}", B64URL.encode(&bytes));
    assert_eq!(
        resolver.resolve(&tampered).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn an_alg_none_token_over_a_real_payload_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let kid = kid_of(&token);
    let resolver = resolver(|_| {});
    for signature in ["", "AAAA"] {
        let forged = forge(
            serde_json::json!({ "alg": "none", "typ": "JWT", "kid": kid }),
            &token,
            signature,
        );
        assert_eq!(
            resolver.resolve(&forged).unwrap_err().code,
            CommandErrorCode::Unauthenticated
        );
    }
}

#[test]
fn an_hmac_token_over_a_real_payload_and_the_realms_own_kid_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Algorithm confusion against live material: the attacker has the realm's
    // public key (a JWKS is public) and its `kid`, signs the untouched payload
    // with HS256, and hopes the verifier takes its algorithm from the header.
    let token = scoped_token();
    let kid = kid_of(&token);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid);
    let forged = jsonwebtoken::encode(
        &header,
        &claims_of(&token),
        &jsonwebtoken::EncodingKey::from_secret(b"the realm public key would go here"),
    )
    .expect("forgery must encode");
    assert_eq!(
        resolver(|_| {}).resolve(&forged).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn a_token_whose_audience_is_another_service_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-wrong-audience",
        "apex-control-lab-wrong-audience-secret",
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

/// The rule the vault doc's principle translates to at this boundary: an
/// identity-provider claim can never confer the `*` global operator scope.
#[test]
fn a_real_token_carrying_a_wildcard_scope_claim_is_refused_outright() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-overbroad",
        "apex-control-lab-overbroad-secret",
    );
    assert_eq!(
        claims_of(&token)["apex_control_scopes"],
        serde_json::json!(["*"]),
        "the fixture client must actually emit a wildcard scope claim"
    );
    // Not narrowed to nothing, not partially honoured: refused.
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

/// Break-glass needs the role *and* the locally-configured subject
/// allow-list. The role alone is the realistic failure -- an over-broad
/// group-to-role mapping in Keycloak -- and it must not be enough.
#[test]
fn the_break_glass_role_alone_does_not_confer_the_global_scope() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-break-glass",
        "apex-control-lab-break-glass-secret",
    );
    let roles = claims_of(&token)["realm_access"]["roles"].clone();
    assert!(
        roles
            .as_array()
            .expect("realm_access.roles must be an array")
            .iter()
            .any(|role| role == "apex-control-break-glass"),
        "the fixture client must actually carry the break-glass realm role: {roles}"
    );
    let subject = subject_of(&token);

    // Role present, subject not allow-listed: narrow scopes only.
    let not_allow_listed = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = ["00000000-0000-4000-8000-000000000000".to_owned()]
            .into_iter()
            .collect();
    });
    let caller = not_allow_listed
        .resolve(&token)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(
        !caller.allows_scope("someone-elses-workspace", "prod"),
        "a Keycloak role must not confer the global operator scope on its own"
    );

    // Role present and subject allow-listed: global.
    let allow_listed = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = [subject.clone()].into_iter().collect();
    });
    let caller = allow_listed
        .resolve(&token)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("someone-elses-workspace", "prod"));

    // Allow-listed but the role withdrawn in Keycloak: back to narrow scopes.
    // This is the revocation path -- removing the role has to be sufficient.
    let scoped = scoped_token();
    let scoped_subject = subject_of(&scoped);
    let both_configured = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = [scoped_subject].into_iter().collect();
    });
    let caller = both_configured
        .resolve(&scoped)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));
}

// ---------------------------------------------------------------------------
// Half two: the deployed container.
// ---------------------------------------------------------------------------

fn oidc_endpoint() -> String {
    std::env::var("APEX_CONTROL_LIVE_OIDC_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:18449".to_owned())
}

fn tls_config() -> ClientTlsConfig {
    let root = secrets_dir();
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret(&root, "ca.pem")))
        .domain_name("localhost")
        .identity(Identity::from_pem(
            require_secret(&root, "control-operator-client.pem"),
            require_secret(&root, "control-operator-client.key"),
        ))
}

async fn submit(token: &str) -> Result<proto::ControlCommandResponse, tonic::Status> {
    let channel = Endpoint::from_shared(oidc_endpoint())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .connect()
        .await
        .expect("the OIDC control gateway must be reachable over mTLS");
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::ControlCommandRequest {
        command_id: Some(uuid::Uuid::now_v7().to_string()),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-keycloak-agent".to_owned(),
        run_id: "live-keycloak-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-keycloak-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    client.submit_command(request).await.map(|r| r.into_inner())
}

/// The deployed selection path. This container is configured with
/// `APEX_CONTROL_KEYCLOAK_ISSUER` and *no* static token table -- setting both
/// is a hard startup error -- so if `build_operator_resolver` did not actually
/// choose the Keycloak resolver, the container would authenticate nobody.
#[tokio::test]
async fn the_deployed_container_accepts_a_real_keycloak_operator_credential() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let token = scoped_token();
    let response = submit(&token)
        .await
        .expect("a real Keycloak operator credential must be accepted by the container");
    assert!(!response.duplicate);
    assert!(!response.command_id.is_empty());
}

/// ... and the scope in the credential is enforced by the container, not just
/// derived by it. The lab realm grants `acme/prod` only.
#[tokio::test]
async fn the_deployed_container_enforces_the_scope_the_credential_carries() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let token = scoped_token();
    let channel = Endpoint::from_shared(oidc_endpoint())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .expect("reachable");
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::ControlCommandRequest {
        command_id: Some(uuid::Uuid::now_v7().to_string()),
        workspace_id: "someone-elses-workspace".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-keycloak-agent".to_owned(),
        run_id: "live-keycloak-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-keycloak-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    let status = client
        .submit_command(request)
        .await
        .expect_err("a scope the credential does not hold must be refused");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

/// The static lab credential must be worthless against a Keycloak-configured
/// container. Otherwise "the production path is wired up" would be compatible
/// with the static table still being live alongside it.
#[tokio::test]
async fn the_deployed_container_refuses_the_static_lab_operator_token() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let table = String::from_utf8(require_secret(&secrets_dir(), "control-operator-tokens"))
        .expect("operator token table must be UTF-8");
    let static_token = table
        .split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .expect("at least one entry")
        .rsplit_once('|')
        .expect("token|scopes")
        .0
        .to_owned();
    let status = submit(&static_token)
        .await
        .expect_err("a static table token must not authenticate against Keycloak");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
