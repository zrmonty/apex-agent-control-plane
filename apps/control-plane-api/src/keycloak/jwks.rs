//! JWKS retrieval: the background-refreshed cache
//! [`super::KeycloakOperatorCredentialResolver`] verifies tokens against, and
//! the bounded, CA-pinned HTTPS client that keeps it populated.

use std::io::Read;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;

use super::config::{KeycloakConfig, KeycloakConfigError};
use super::{
    JWKS_CONNECT_TIMEOUT, JWKS_REQUEST_TIMEOUT, JWKS_RETRY_DELAY, MAX_JWKS_BYTES, MAX_JWKS_KEYS,
};

#[derive(Debug, Default)]
pub(super) struct JwksCache {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl JwksCache {
    pub(super) fn store(&mut self, keys: JwkSet) {
        self.keys = Some(keys);
        self.fetched_at = Some(Instant::now());
    }

    /// The cached set, or `None` when it is absent or older than `max_age`.
    /// Absence is what makes this resolver fail closed.
    pub(super) fn fresh(&self, max_age: Duration) -> Option<&JwkSet> {
        match (&self.keys, self.fetched_at) {
            (Some(keys), Some(at)) if at.elapsed() <= max_age => Some(keys),
            _ => None,
        }
    }
}

/// HTTPS client for the JWKS endpoint, trusting only the configured CA.
pub(super) fn build_jwks_client(
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

pub(super) fn fetch_jwks(
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
pub(super) fn spawn_jwks_refresher(
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
