use crate::browser::errors::BrowserError;
use url::Url;
use zeroize::Zeroizing;

/// Only startup builds this configuration; HTTP inputs cannot select endpoints,
/// audiences, credentials or redirects. Redirect URI is fixed at /auth/callback.
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub public_origin: String,
    pub provider_ca_pem: Vec<u8>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
}

impl OidcConfig {
    pub fn validate(&self) -> Result<(), BrowserError> {
        crate::browser::security::ConfiguredOrigin::parse(&self.public_origin)
            .map_err(|_| BrowserError::Unavailable)?;
        for value in [
            &self.issuer,
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.jwks_uri,
            &self.revocation_endpoint,
        ] {
            trusted_https_url(value)?;
        }
        if self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.client_id == "account"
            || !self.client_id.bytes().all(|c| c.is_ascii_graphic())
            || !(16..=4096).contains(&self.client_secret.len())
            || !self.client_secret.bytes().all(|c| c.is_ascii_graphic())
            || self.provider_ca_pem.is_empty()
            || self.provider_ca_pem.len() > 1024 * 1024
        {
            return Err(BrowserError::Unavailable);
        }
        Ok(())
    }
    pub fn callback_uri(&self) -> Result<Url, BrowserError> {
        self.validate()?;
        Url::parse(&format!("{}/auth/callback", self.public_origin))
            .map_err(|_| BrowserError::Unavailable)
    }
    pub fn discovery_uri(&self) -> Result<Url, BrowserError> {
        self.validate()?;
        Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        ))
        .map_err(|_| BrowserError::Unavailable)
    }
    /// Check the discovery document's literal issuer before any JWKS fetch.
    /// Endpoint equality is against explicit deployment configuration, not an
    /// issuer document's assertion that an arbitrary URL should be trusted.
    pub fn validate_discovery(&self, json: &[u8]) -> Result<openid::Config, BrowserError> {
        self.validate()?;
        if json.len() > 65536 {
            return Err(BrowserError::Unavailable);
        }
        let value =
            crate::contract_json::parse_unique_json(json).map_err(|_| BrowserError::Unavailable)?;
        for (name, expected) in [
            ("issuer", &self.issuer),
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
            ("revocation_endpoint", &self.revocation_endpoint),
        ] {
            if value.get(name).and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
                return Err(BrowserError::Unavailable);
            }
        }
        for (name, required) in [
            ("response_types_supported", &["code"][..]),
            ("response_modes_supported", &["query"][..]),
            (
                "grant_types_supported",
                &["authorization_code", "refresh_token"][..],
            ),
            ("id_token_signing_alg_values_supported", &["RS256"][..]),
            (
                "token_endpoint_auth_methods_supported",
                &["client_secret_basic"][..],
            ),
            (
                "revocation_endpoint_auth_methods_supported",
                &["client_secret_basic"][..],
            ),
            ("code_challenge_methods_supported", &["S256"][..]),
            ("scopes_supported", &["openid"][..]),
        ] {
            let entries = value
                .get(name)
                .and_then(serde_json::Value::as_array)
                .ok_or(BrowserError::Unavailable)?;
            if entries.len() > 64
                || entries
                    .iter()
                    .any(|entry| entry.as_str().is_none_or(|text| text.len() > 256))
                || required
                    .iter()
                    .any(|required| !entries.iter().any(|entry| entry.as_str() == Some(required)))
            {
                return Err(BrowserError::Unavailable);
            }
        }
        serde_json::from_value(value).map_err(|_| BrowserError::Unavailable)
    }
}

pub(super) fn trusted_https_url(raw: &str) -> Result<Url, BrowserError> {
    if raw.is_empty()
        || raw.len() > 2048
        || !raw.bytes().all(|byte| byte.is_ascii_graphic())
        || !raw.starts_with("https://")
        || raw.contains(['\\', '%', '?', '#'])
        || raw.split('/').any(|part| part == "." || part == "..")
    {
        return Err(BrowserError::Unavailable);
    }
    let value = Url::parse(raw).map_err(|_| BrowserError::Unavailable)?;
    let authority = raw
        .trim_start_matches("https://")
        .split('/')
        .next()
        .ok_or(BrowserError::Unavailable)?;
    crate::browser::security::ConfiguredOrigin::parse(&format!("https://{authority}"))
        .map_err(|_| BrowserError::Unavailable)?;
    Ok(value)
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcConfig([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) mod tests;
