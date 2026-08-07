//! Keycloak-backed operator credential verification.
//!
//! Per [[Authentication and Identity]] in the product vault, Keycloak is the
//! human/workforce identity broker: the GUI authenticates through OIDC
//! authorization-code + PKCE, and an operator (or a CLI/automation acting for
//! one) obtains a **short-lived, scope-bound operator credential** for this
//! gRPC service through RFC 8693 token exchange. Keycloak performs that
//! exchange. This gateway is a **resource server**: it never talks OAuth on
//! behalf of anyone, holds no client secret, and does nothing but *verify* a
//! token Keycloak already issued. That is the whole job of this module.
//!
//! [`crate::auth::StaticOperatorTokenResolver`] remains the local/lab and CI
//! seam and is untouched; this is the third, explicitly-configured production
//! path (`startup::env::operator_credential_source`).
//!
//! # Verification rules, and why each one is here
//!
//! JWT verification is one of the highest-value places in a system to get
//! wrong, and the failures are well known. Each is closed explicitly rather
//! than by relying on a library default:
//!
//! - **Algorithm confusion.** The permitted algorithm is derived from the
//!   *JWK* (`alg` in the JWKS entry), never from the token's own header. The
//!   header's `alg` must then equal it. `alg: none` cannot even parse --
//!   [`jsonwebtoken::Algorithm`] has no such variant -- and a symmetric
//!   (`oct`/HS*) JWKS entry is refused outright, because "present the RSA
//!   public key as an HMAC secret" is exactly the classic attack and there is
//!   no legitimate reason for a symmetric key to appear in an OIDC signing
//!   JWKS.
//! - **Missing issuer/audience checks.** `iss` and `aud` are both *required*
//!   claims here, not merely validated-if-present, which is
//!   [`jsonwebtoken::Validation`]'s default. A token from another realm, or
//!   one minted for a different client, is refused.
//! - **Token-type confusion.** Keycloak signs ID tokens, access tokens and
//!   refresh tokens with the *same* realm keys. An ID token's `aud` is the
//!   client id, so a gateway whose expected audience is its client id would
//!   otherwise accept an ID token as an operator credential. The payload
//!   `typ` claim must equal the configured value (`Bearer` by default).
//! - **Accepting long-lived tokens.** The doc's requirement is a *short-lived*
//!   credential, so `exp - iat` is bounded by
//!   `APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS`. Signature validity alone
//!   would happily accept a ten-year token.
//! - **Stale keys.** The JWKS is cached and refreshed on an interval, so a key
//!   Keycloak has rotated away stops validating within a bounded window rather
//!   than "when the process restarts". If refreshes stop succeeding, the cache
//!   goes stale and this resolver **fails closed** rather than trusting keys of
//!   unknown age.
//!
//! # Claim-to-scope mapping
//!
//! The vault doc's stated principle for the rest of the system is that
//! "Identity-provider claims are untrusted input until mapped through explicit
//! allow-listed claim/group rules... External claims can never automatically
//! confer Owner." The equivalent rule at this boundary is that **no claim can
//! automatically confer the `*` global/break-glass operator scope**:
//!
//! - The scope claim maps only to *narrow* `workspace/namespace` grants. A
//!   scope entry containing `*` does not widen anything -- it **rejects the
//!   whole token**, because a wildcard there means either a
//!   misconfigured mapper or an attempt, and silently dropping the entry would
//!   hand back a partial grant nobody asked for.
//! - `*` requires all three of: `APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE`
//!   configured, the token's `sub` present in the locally-configured
//!   `APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS` allow-list, and that role present
//!   in the token's allow-listed role claim. Any of the three unset or absent
//!   means no global scope, ever. The local subject allow-list is the part
//!   that is *not* IdP-controlled: it means an over-broad group-to-role
//!   mapping in Keycloak -- the realistic failure -- cannot by itself hand
//!   anyone break-glass rights over every workspace. It is deliberately not a
//!   defence against a fully compromised Keycloak, which can mint any `sub` it
//!   likes; nothing an OIDC resource server does defends against that, and
//!   claiming otherwise would be dishonest.

use std::collections::BTreeSet;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::auth::{OperatorCaller, OperatorCredentialResolver};
use crate::errors::CommandError;

/// Clock skew allowed on `exp`/`nbf`/`iat`.
///
/// Not zero: the gateway and Keycloak are separate hosts, and a gateway whose
/// clock is a fraction of a second behind would otherwise refuse a
/// freshly-minted token outright. Not large either -- 30s against a credential
/// that is supposed to live for minutes is a rounding error, whereas
/// `jsonwebtoken`'s own 60s default is a meaningful fraction of a 5-minute
/// Keycloak access token's life.
const CLOCK_SKEW_LEEWAY_SECS: u64 = 30;

/// Bounds on untrusted material. A bearer header is already capped at 4096
/// bytes by `auth::extract_bearer_token`; this is the same ceiling restated
/// where the token is parsed.
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_KID_BYTES: usize = 256;
const MAX_SUBJECT_CLAIM_BYTES: usize = 200;
/// A JWKS is a small document. Keycloak publishes two or three keys.
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 32;
/// Matches `auth::MAX_ALLOWED_SCOPES`; refused before allocating rather than
/// after, so an inflated claim cannot make this process build a huge vector.
const MAX_CLAIM_SCOPES: usize = 256;
const MAX_CLAIM_ROLES: usize = 512;
/// Deepest dotted claim path traversed (`resource_access.apex-control.roles`
/// is three).
const MAX_CLAIM_PATH_DEPTH: usize = 8;

/// How long a JWKS fetch may take before it is abandoned. Bounded because the
/// refresher owns no request, but an unbounded read against a hung Keycloak
/// would silently stop all future refreshes.
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Retry sooner than the configured interval after a failed refresh, so a
/// transient Keycloak blip does not leave the cache to age out.
const JWKS_RETRY_DELAY: Duration = Duration::from_secs(15);

/// Why a presented credential was refused. Static strings only: no token, no
/// claim value, and no subject ever reaches a log line through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeycloakRejection(&'static str);

impl KeycloakRejection {
    pub fn reason(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for KeycloakRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

macro_rules! reject {
    ($reason:literal) => {
        KeycloakRejection($reason)
    };
}

/// A refused Keycloak resolver configuration. Carries a static reason and
/// never the configured URL, audience, or any secret material -- startup
/// errors are printed, and this is the one place a misconfiguration could
/// otherwise leak an internal issuer URL into a log aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeycloakConfigError(&'static str);

impl std::fmt::Display for KeycloakConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid Keycloak operator credential configuration: {}", self.0)
    }
}

impl std::error::Error for KeycloakConfigError {}

/// Verifier configuration.
///
/// The CA arrives as **PEM bytes**, not a path, on purpose: path confinement
/// under `APEX_CONTROL_TRUSTED_SECRET_BASE` lives in the binary's
/// `startup::secrets`, which is not part of this library crate. Doing the
/// reading there and passing bytes here keeps exactly one implementation of
/// the trusted-secret policy instead of a second, subtly different one.
#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    /// Exact expected `iss`, e.g. `https://sso.example.com/realms/apex`.
    pub issuer: String,
    /// Exact expected member of `aud` -- this gateway's client/audience.
    pub audience: String,
    /// Where the signing keys are fetched from. Defaults to
    /// `{issuer}/protocol/openid-connect/certs` (see
    /// [`KeycloakConfig::default_jwks_url`]).
    pub jwks_url: String,
    /// CA that the JWKS endpoint's server certificate must chain to. The
    /// client trusts *only* this, never a platform root store.
    pub jwks_ca_pem: Vec<u8>,
    /// Background refresh interval. Also the upper bound on how long a key
    /// Keycloak has rotated away keeps validating, while refreshes succeed.
    pub jwks_refresh: Duration,
    /// Hard staleness ceiling. Once the cached JWKS is older than this the
    /// resolver refuses every credential rather than trusting keys of unknown
    /// age -- the bounded window for a *compromised* key, when refreshes are
    /// failing.
    pub jwks_max_age: Duration,
    /// Dotted path to the allow-listed scope claim.
    pub scope_claim: String,
    /// Dotted path to the allow-listed role claim (`realm_access.roles` for a
    /// Keycloak realm role).
    pub role_claim: String,
    /// Role that, together with a `sub` in [`Self::global_subjects`], maps to
    /// the `*` break-glass scope. `None` means `*` is unreachable.
    pub global_role: Option<String>,
    /// Locally-configured `sub` allow-list for the `*` scope. Empty means `*`
    /// is unreachable.
    pub global_subjects: BTreeSet<String>,
    /// Ceiling on `exp - iat`.
    pub max_token_lifetime: Duration,
    /// Required payload `typ`. `None` disables the check (explicitly opting
    /// out of ID-token/refresh-token confusion protection).
    pub expected_typ: Option<String>,
}

impl KeycloakConfig {
    /// The standard Keycloak JWKS location for a realm issuer.
    pub fn default_jwks_url(issuer: &str) -> String {
        format!(
            "{}/protocol/openid-connect/certs",
            issuer.trim_end_matches('/')
        )
    }

    /// Rejects a configuration that could never verify anything, or that would
    /// verify the wrong thing.
    ///
    /// Deliberately **not** a same-origin requirement between the issuer and
    /// the JWKS URL. Split-horizon deployments legitimately publish an
    /// external issuer (`https://sso.example.com/realms/apex`) while resolving
    /// keys over an internal service address, and a same-origin rule would
    /// break that for no gain: an attacker who can rewrite this process's
    /// environment can rewrite the issuer and audience too, so the rule would
    /// only ever catch an operator typo -- which the `iss` check already
    /// catches, because keys from the wrong realm do not carry the right
    /// `kid`, and a token from the wrong realm fails the issuer comparison
    /// regardless. Overriding the JWKS URL is an assertion that it serves the
    /// configured issuer's keys, and is documented as such.
    pub fn validate(&self) -> Result<(), KeycloakConfigError> {
        check_https_url(&self.issuer, "APEX_CONTROL_KEYCLOAK_ISSUER")?;
        check_https_url(&self.jwks_url, "APEX_CONTROL_KEYCLOAK_JWKS_URL")?;
        if self.audience.is_empty()
            || self.audience.len() > 256
            || !self.audience.is_ascii()
            || self.audience.chars().any(char::is_control)
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_AUDIENCE must be non-empty printable ASCII under 256 bytes",
            ));
        }
        // `account` is on the `aud` of essentially every token Keycloak issues
        // in a realm, by default. Configuring it as *this* gateway's expected
        // audience makes the audience check vacuous: any token for any client
        // in the realm would satisfy it. That is not a hypothetical typo --
        // it is the value an operator reads out of a decoded token and copies
        // when they are not sure which of the two entries is theirs.
        if self.audience == "account" {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_AUDIENCE must not be 'account': Keycloak puts that on every token in the realm, so the audience check would accept any client's token",
            ));
        }
        if self.jwks_ca_pem.is_empty() {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_CA_FILE produced no certificate material",
            ));
        }
        check_claim_path(&self.scope_claim, "APEX_CONTROL_KEYCLOAK_SCOPE_CLAIM")?;
        check_claim_path(&self.role_claim, "APEX_CONTROL_KEYCLOAK_ROLE_CLAIM")?;
        if let Some(role) = &self.global_role
            && (role.is_empty() || role.len() > 256 || !role.is_ascii())
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE must be non-empty ASCII under 256 bytes",
            ));
        }
        if self.global_subjects.len() > 64 {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS lists more than 64 break-glass subjects",
            ));
        }
        for subject in &self.global_subjects {
            if subject.is_empty()
                || subject.len() > MAX_SUBJECT_CLAIM_BYTES
                || !subject.is_ascii()
                || subject.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(KeycloakConfigError(
                    "APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS contains a malformed subject",
                ));
            }
        }
        // A `*` grant that nobody can reach is fine and is the default. A
        // half-configured one is not: it reads like break-glass is set up when
        // it is not, and the operator finds out during the incident.
        if self.global_role.is_some() == self.global_subjects.is_empty() {
            return Err(KeycloakConfigError(
                "set APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE and APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS together, or neither",
            ));
        }
        if self.jwks_refresh.is_zero() || self.jwks_max_age < self.jwks_refresh {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS must be at least the refresh interval",
            ));
        }
        if self.max_token_lifetime.is_zero() {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS must be positive",
            ));
        }
        if let Some(typ) = &self.expected_typ
            && (typ.len() > 64 || !typ.is_ascii() || typ.chars().any(char::is_control))
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_EXPECTED_TYP must be short printable ASCII",
            ));
        }
        Ok(())
    }
}

fn check_https_url(raw: &str, label: &'static str) -> Result<(), KeycloakConfigError> {
    let _ = label;
    if raw.len() > 512
        || !raw.is_ascii()
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(KeycloakConfigError(
            "issuer/JWKS URL must be printable ASCII under 512 bytes",
        ));
    }
    let url = reqwest::Url::parse(raw)
        .map_err(|_| KeycloakConfigError("issuer/JWKS URL is not a URL"))?;
    // Plaintext is refused with no escape hatch, matching every other
    // transport this crate opens. A JWKS fetched over HTTP is a set of signing
    // keys an on-path attacker chooses.
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(KeycloakConfigError(
            "issuer/JWKS URL must be https with no credentials or fragment",
        ));
    }
    Ok(())
}

fn check_claim_path(path: &str, label: &'static str) -> Result<(), KeycloakConfigError> {
    let _ = label;
    let segments: Vec<&str> = path.split('.').collect();
    if path.is_empty()
        || path.len() > 256
        || !path.is_ascii()
        || segments.len() > MAX_CLAIM_PATH_DEPTH
        || segments.iter().any(|segment| segment.is_empty())
    {
        return Err(KeycloakConfigError(
            "claim path must be 1..=8 non-empty dot-separated ASCII segments",
        ));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct JwksCache {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl JwksCache {
    fn store(&mut self, keys: JwkSet) {
        self.keys = Some(keys);
        self.fetched_at = Some(Instant::now());
    }

    /// The cached set, or `None` when it is absent or older than `max_age`.
    /// Absence is what makes this resolver fail closed.
    fn fresh(&self, max_age: Duration) -> Option<&JwkSet> {
        match (&self.keys, self.fetched_at) {
            (Some(keys), Some(at)) if at.elapsed() <= max_age => Some(keys),
            _ => None,
        }
    }
}

/// Verifies short-lived, scope-bound operator credentials issued by Keycloak.
pub struct KeycloakOperatorCredentialResolver {
    config: Arc<KeycloakConfig>,
    cache: Arc<RwLock<JwksCache>>,
    /// Millisecond timestamp of the last rejection log line, so a credential
    /// flood cannot turn this into a log amplifier. The auth-failure bucket in
    /// `OperatorTokenAuthenticator` throttles per token digest; this throttles
    /// the aggregate.
    last_rejection_log_ms: AtomicU64,
}

impl KeycloakOperatorCredentialResolver {
    /// Validates configuration, performs a best-effort first JWKS fetch, and
    /// starts the background refresher.
    ///
    /// **Must be called with no tokio runtime entered.** The JWKS client is
    /// `reqwest::blocking`, which owns an internal runtime; constructing one on
    /// a runtime thread panics. `startup::service::run` is synchronous for
    /// exactly this class of reason and builds the serving runtime afterwards.
    ///
    /// A failed *first* fetch is a warning, not a startup failure. Refusing to
    /// start would make Keycloak a hard startup dependency of the one channel
    /// that must stay reachable when the rest of the platform is degraded
    /// (ADR-0006), and would turn a 30-second IdP blip into an outage that
    /// needs a human to notice and restart a container. The resolver instead
    /// comes up refusing every credential with a distinct, honest
    /// `CREDENTIAL_VERIFIER_UNAVAILABLE`, and begins working the moment a
    /// refresh succeeds. Configuration errors still abort startup loudly --
    /// same split as `NatsTlsConfig` (eager config validation, deferred
    /// connection).
    pub fn start(config: KeycloakConfig) -> Result<Self, KeycloakConfigError> {
        config.validate()?;
        let config = Arc::new(config);
        let client = build_jwks_client(&config)?;
        let cache = Arc::new(RwLock::new(JwksCache::default()));
        let mut fetched = false;
        match fetch_jwks(&client, &config) {
            Ok(keys) => {
                if let Ok(mut guard) = cache.write() {
                    guard.store(keys);
                    fetched = true;
                }
            }
            Err(reason) => eprintln!(
                "control-plane-api: initial Keycloak JWKS fetch failed ({reason}); operator credentials are refused until a refresh succeeds"
            ),
        }
        spawn_jwks_refresher(client, Arc::clone(&config), Arc::downgrade(&cache), fetched);
        Ok(Self {
            config,
            cache,
            last_rejection_log_ms: AtomicU64::new(0),
        })
    }

    /// Builds a resolver over a fixed, already-known JWKS: no HTTP client and
    /// no refresher thread. Tests only -- a deployment must be able to pick up
    /// a key rotation without a restart.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_static_jwks(config: KeycloakConfig, keys: JwkSet) -> Result<Self, KeycloakConfigError> {
        config.validate()?;
        let mut cache = JwksCache::default();
        cache.store(keys);
        Ok(Self {
            config: Arc::new(config),
            cache: Arc::new(RwLock::new(cache)),
            last_rejection_log_ms: AtomicU64::new(0),
        })
    }

    /// True once a JWKS has been fetched and is still inside its staleness
    /// ceiling. Exposed so a live test can wait for the verifier to be ready
    /// instead of racing the first fetch.
    pub fn keys_are_fresh(&self) -> bool {
        self.cache
            .read()
            .is_ok_and(|cache| cache.fresh(self.config.jwks_max_age).is_some())
    }

    fn log_rejection(&self, rejection: KeycloakRejection) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last = self.last_rejection_log_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 1_000 {
            return;
        }
        if self
            .last_rejection_log_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            eprintln!(
                "control-plane-api: refused a Keycloak operator credential ({})",
                rejection.reason()
            );
        }
    }
}

impl OperatorCredentialResolver for KeycloakOperatorCredentialResolver {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError> {
        let Ok(cache) = self.cache.read() else {
            // A poisoned lock fails closed, never into an unverified accept.
            return Err(CommandError::internal());
        };
        let Some(keys) = cache.fresh(self.config.jwks_max_age) else {
            // Deliberately distinguishable from "your credential is bad": an
            // operator holding a perfectly good token during an IdP outage
            // should be told the verifier cannot check it, not that they are
            // unauthenticated. It reveals nothing an attacker does not already
            // learn by watching every request fail.
            return Err(CommandError::credential_verifier_unavailable());
        };
        match verify_token(&self.config, keys, token) {
            Ok(caller) => Ok(caller),
            Err(rejection) => {
                drop(cache);
                self.log_rejection(rejection);
                // One error for every verification failure. A prober must not
                // be able to tell a bad signature from a wrong audience from a
                // scope claim that was refused.
                Err(CommandError::unauthenticated())
            }
        }
    }
}

/// The single verification routine. Pure over `(config, keys, token)` plus the
/// system clock, so every rejection case below is unit-testable without a
/// network or a live Keycloak.
pub(crate) fn verify_token(
    config: &KeycloakConfig,
    keys: &JwkSet,
    token: &str,
) -> Result<OperatorCaller, KeycloakRejection> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(reject!("TOKEN_SIZE"));
    }
    // `decode_header` refuses `alg: none` on its own: `jsonwebtoken::Algorithm`
    // has no `none` variant, so the header fails to deserialize. Asserted by
    // `alg_none_token_is_refused` rather than assumed.
    let header = decode_header(token).map_err(|_| reject!("MALFORMED_HEADER"))?;
    let Some(kid) = header.kid.as_deref() else {
        // Without a `kid` the only options are "try every key" (which turns a
        // key set into an oracle and costs one signature verification per key
        // per bad token) or "guess". Keycloak always publishes one.
        return Err(reject!("MISSING_KID"));
    };
    if kid.is_empty() || kid.len() > MAX_KID_BYTES {
        return Err(reject!("KID_SIZE"));
    }
    let jwk = keys.find(kid).ok_or(reject!("UNKNOWN_KID"))?;
    let algorithm = signing_algorithm_for(jwk)?;
    // The token does not get to choose. The JWK does, and the header must
    // agree with it.
    if header.alg != algorithm {
        return Err(reject!("HEADER_ALG_DOES_NOT_MATCH_JWK"));
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| reject!("UNUSABLE_JWK"))?;

    let mut validation = Validation::new(algorithm);
    // Exactly one permitted algorithm, taken from the JWK.
    validation.algorithms = vec![algorithm];
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    // `Validation` only checks `iss`/`aud` when the claim is *present*. Making
    // them required is what turns those from advisory into enforced.
    validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
        .iter()
        .map(|claim| (*claim).to_owned())
        .collect();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.leeway = CLOCK_SKEW_LEEWAY_SECS;

    let data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|_| reject!("SIGNATURE_OR_REGISTERED_CLAIMS"))?;
    let claims = data
        .claims
        .as_object()
        .ok_or(reject!("CLAIMS_NOT_AN_OBJECT"))?;

    if let Some(expected) = &config.expected_typ {
        let typ = claims.get("typ").and_then(serde_json::Value::as_str);
        if typ != Some(expected.as_str()) {
            // An ID token or a refresh token carries the same realm signature
            // and, for an ID token, an `aud` equal to the client id.
            return Err(reject!("UNEXPECTED_TOKEN_TYP"));
        }
    }

    let now = unix_now();
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or(reject!("MISSING_EXP"))?;
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or(reject!("MISSING_IAT"))?;
    if exp <= iat {
        return Err(reject!("NONSENSICAL_LIFETIME"));
    }
    if iat.saturating_sub(now) > CLOCK_SKEW_LEEWAY_SECS as i64 {
        return Err(reject!("IAT_IN_THE_FUTURE"));
    }
    if exp.saturating_sub(iat) as u64 > config.max_token_lifetime.as_secs() {
        return Err(reject!("TOKEN_LIFETIME_EXCEEDS_CEILING"));
    }

    let subject_claim = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or(reject!("MISSING_SUB"))?;
    if subject_claim.is_empty() || subject_claim.len() > MAX_SUBJECT_CLAIM_BYTES {
        return Err(reject!("SUB_SIZE"));
    }
    // Prefixed so the audit trail distinguishes a Keycloak-issued operator
    // from a static table entry (`operator:static:<n>`) at a glance.
    // `OperatorCaller` enforces the ingest actor-identifier grammar on the
    // result, so a `sub` containing a space or a slash is refused here rather
    // than turning every command that operator sends into INVALID_COMMAND.
    let subject = format!("operator:keycloak:{subject_claim}");

    let scopes = scope_grants(config, claims)?;
    let roles = role_grants(config, claims)?;
    let global = match (&config.global_role, config.global_subjects.is_empty()) {
        (Some(role), false) => {
            config.global_subjects.contains(subject_claim)
                && roles.iter().any(|held| held == role)
        }
        _ => false,
    };

    if global {
        return OperatorCaller::global(subject).map_err(|_| reject!("SUBJECT_GRAMMAR"));
    }
    if scopes.is_empty() {
        // A credential that can act nowhere is a configuration failure, and
        // saying so at the credential boundary beats every command coming back
        // SCOPE_DENIED with no hint why.
        return Err(reject!("NO_MAPPED_SCOPES"));
    }
    OperatorCaller::scoped(subject, scopes).map_err(|_| reject!("SCOPE_GRAMMAR"))
}

/// The one algorithm this JWK may be used with, or a rejection.
fn signing_algorithm_for(jwk: &Jwk) -> Result<Algorithm, KeycloakRejection> {
    // Keycloak publishes an encryption key (RSA-OAEP) alongside the signing
    // key in the same JWKS. `use: enc` must never verify a token.
    if let Some(usage) = &jwk.common.public_key_use
        && *usage != PublicKeyUse::Signature
    {
        return Err(reject!("JWK_NOT_FOR_SIGNATURES"));
    }
    // A symmetric entry in a signing JWKS is the algorithm-confusion attack in
    // its most direct form: the verifier is handed key material it will treat
    // as an HMAC secret, and the attacker knows it because a JWKS is public.
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(reject!("SYMMETRIC_JWK_REFUSED"));
    }
    let Some(key_algorithm) = jwk.common.key_algorithm else {
        // Without `alg` on the JWK there is nothing to pin the token's header
        // against except the token itself, which is the thing being checked.
        return Err(reject!("JWK_WITHOUT_ALG"));
    };
    match key_algorithm {
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        // HS* and the RSA encryption algorithms are enumerated as refusals
        // rather than caught by a `_` arm, so adding a variant upstream is a
        // compile error here instead of a silent widening.
        KeyAlgorithm::HS256
        | KeyAlgorithm::HS384
        | KeyAlgorithm::HS512
        | KeyAlgorithm::RSA1_5
        | KeyAlgorithm::RSA_OAEP
        | KeyAlgorithm::RSA_OAEP_256 => Err(reject!("DISALLOWED_JWK_ALG")),
    }
}

/// Allow-listed `workspace/namespace` grants from the configured scope claim.
///
/// Accepts a JSON array of strings or a single space-separated string (the
/// OAuth `scope` shape), because a Keycloak protocol mapper can produce
/// either. Anything else is a rejection, not an empty result.
fn scope_grants(
    config: &KeycloakConfig,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>, KeycloakRejection> {
    let raw = match claim_at(claims, &config.scope_claim) {
        None => return Ok(Vec::new()),
        Some(value) => value,
    };
    let mut scopes: Vec<String> = Vec::new();
    match raw {
        serde_json::Value::Array(items) => {
            if items.len() > MAX_CLAIM_SCOPES {
                return Err(reject!("TOO_MANY_SCOPE_CLAIMS"));
            }
            for item in items {
                let entry = item.as_str().ok_or(reject!("MALFORMED_SCOPE_CLAIM"))?;
                scopes.push(entry.to_owned());
            }
        }
        serde_json::Value::String(raw) => {
            for entry in raw.split_whitespace() {
                if scopes.len() >= MAX_CLAIM_SCOPES {
                    return Err(reject!("TOO_MANY_SCOPE_CLAIMS"));
                }
                scopes.push(entry.to_owned());
            }
        }
        _ => return Err(reject!("MALFORMED_SCOPE_CLAIM")),
    }
    // The load-bearing rule. A wildcard in an IdP-controlled claim rejects the
    // whole credential; it never widens, and it is never quietly dropped.
    // Dropping it would hand back a narrower grant than the token asked for
    // and leave nobody aware the mapper is wrong.
    if scopes.iter().any(|scope| scope.contains('*')) {
        return Err(reject!("WILDCARD_IN_SCOPE_CLAIM"));
    }
    scopes.retain(|scope| !scope.is_empty());
    Ok(scopes)
}

fn role_grants(
    config: &KeycloakConfig,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>, KeycloakRejection> {
    let Some(raw) = claim_at(claims, &config.role_claim) else {
        return Ok(Vec::new());
    };
    let serde_json::Value::Array(items) = raw else {
        return Err(reject!("MALFORMED_ROLE_CLAIM"));
    };
    if items.len() > MAX_CLAIM_ROLES {
        return Err(reject!("TOO_MANY_ROLE_CLAIMS"));
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(reject!("MALFORMED_ROLE_CLAIM"))
        })
        .collect()
}

/// Resolves a dotted claim path against the token's claim object.
///
/// Only JSON *objects* are traversed. A claim whose own name contains a `.`
/// is therefore unaddressable, which is documented at the config surface --
/// the alternative (trying both interpretations) would make which claim is
/// consulted depend on the token's own shape.
fn claim_at<'a>(
    claims: &'a serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut segments = path.split('.');
    let mut current = claims.get(segments.next()?)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// HTTPS client for the JWKS endpoint, trusting only the configured CA.
fn build_jwks_client(
    config: &KeycloakConfig,
) -> Result<reqwest::blocking::Client, KeycloakConfigError> {
    crate::install_rustls_provider();
    let certificate = reqwest::Certificate::from_pem(&config.jwks_ca_pem)
        .map_err(|_| KeycloakConfigError("APEX_CONTROL_KEYCLOAK_CA_FILE is not a PEM certificate"))?;
    reqwest::blocking::Client::builder()
        .use_rustls_tls()
        // Never follow a redirect while fetching signing keys: a redirect is
        // the endpoint choosing where this process gets its trust anchors.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(JWKS_CONNECT_TIMEOUT)
        .timeout(JWKS_REQUEST_TIMEOUT)
        .pool_max_idle_per_host(1)
        // `tls_certs_only`, not `tls_certs_merge`/`add_root_certificate`: the
        // configured CA replaces the trust store rather than being added to
        // it. A JWKS served by anything holding a publicly-trusted
        // certificate must not be able to stand in for the realm's signing
        // keys, and a merge would let it.
        .tls_certs_only([certificate])
        .build()
        .map_err(|_| KeycloakConfigError("could not build the Keycloak JWKS client"))
}

fn fetch_jwks(
    client: &reqwest::blocking::Client,
    config: &KeycloakConfig,
) -> Result<JwkSet, &'static str> {
    let response = client
        .get(&config.jwks_url)
        .header("accept", "application/json")
        .send()
        .map_err(|_| "TRANSPORT")?;
    if !response.status().is_success() {
        return Err("HTTP_STATUS");
    }
    // Bounded read: `bytes()` would happily buffer whatever the endpoint
    // sends. Read one byte past the ceiling so an over-limit body is detected
    // rather than silently truncated into something that still parses.
    let mut body = Vec::with_capacity(8 * 1024);
    response
        .take(MAX_JWKS_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| "BODY_READ")?;
    if body.is_empty() || body.len() > MAX_JWKS_BYTES {
        return Err("BODY_SIZE");
    }
    let keys: JwkSet = serde_json::from_slice(&body).map_err(|_| "MALFORMED_JWKS")?;
    if keys.keys.is_empty() {
        return Err("EMPTY_JWKS");
    }
    if keys.keys.len() > MAX_JWKS_KEYS {
        return Err("TOO_MANY_KEYS");
    }
    Ok(keys)
}

/// Replaces the whole cached set on every successful refresh.
///
/// Replacement, not merge, is the point: a key Keycloak has rotated away stops
/// validating one refresh interval later. Merging would keep a retired -- or
/// compromised and revoked -- key usable for as long as the process lived.
fn spawn_jwks_refresher(
    client: reqwest::blocking::Client,
    config: Arc<KeycloakConfig>,
    cache: Weak<RwLock<JwksCache>>,
    initial_fetch_succeeded: bool,
) {
    let mut delay = if initial_fetch_succeeded {
        config.jwks_refresh
    } else {
        JWKS_RETRY_DELAY.min(config.jwks_refresh)
    };
    let spawned = std::thread::Builder::new()
        .name("apex-control-jwks".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(delay);
                // The resolver has been dropped: stop, rather than keep a
                // process-lifetime thread alive per constructed resolver.
                let Some(cache) = cache.upgrade() else {
                    return;
                };
                match fetch_jwks(&client, &config) {
                    Ok(keys) => {
                        if let Ok(mut guard) = cache.write() {
                            guard.store(keys);
                        }
                        delay = config.jwks_refresh;
                    }
                    Err(reason) => {
                        eprintln!(
                            "control-plane-api: Keycloak JWKS refresh failed ({reason}); cached keys expire at the configured max age"
                        );
                        delay = JWKS_RETRY_DELAY.min(config.jwks_refresh);
                    }
                }
            }
        });
    if spawned.is_err() {
        eprintln!(
            "control-plane-api: could not start the Keycloak JWKS refresher; cached keys will expire and every operator credential will then be refused"
        );
    }
}

#[cfg(test)]
mod tests;
