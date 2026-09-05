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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Only `with_static_jwks` (test/`test-support` only, below) names `JwkSet`
// directly in this file; every non-test path reaches it through `jwks::`.
#[cfg(any(test, feature = "test-support"))]
use jsonwebtoken::jwk::JwkSet;

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

mod config;
mod jwks;
mod verify;

pub use config::{KeycloakConfig, KeycloakConfigError};
use jwks::{JwksCache, build_jwks_client, fetch_jwks, spawn_jwks_refresher};
use verify::verify_token;

#[cfg(test)]
pub(crate) mod tests;
