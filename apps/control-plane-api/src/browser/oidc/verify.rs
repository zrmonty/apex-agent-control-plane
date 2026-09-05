//! ID-token login verification is separate from access-token authorization.
//! Protocol checks use openid; JOSE verification uses its maintained biscuit
//! dependency. Only fixed, freshly fetched provider signing keys enter here.

use super::config::OidcConfig;
use crate::browser::errors::BrowserError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openid::biscuit::{jwa::SignatureAlgorithm, jwk::RSAKeyParameters};
use std::collections::BTreeMap;

mod claims;
mod keys;
mod temporal;

pub enum IdTokenExpectation<'a> {
    Login { nonce: &'a str },
    Refresh { subject: &'a str, original_nonce: &'a str },
}

pub struct VerifiedLogin { pub subject:String, pub expires_at:i64 }

pub struct IdTokenVerifier {
    discovery: openid::Config,
    issuer: String,
    client_id: String,
    keys: BTreeMap<String, RSAKeyParameters>,
}

impl IdTokenVerifier {
    /// Provider documents must come from the bounded, pinned HTTPS transport.
    /// This verifier is per-exchange; it does not cache keys beyond the exchange.
    pub fn new(config:&OidcConfig,discovery:&[u8],jwks:&[u8]) -> Result<Self,BrowserError> {
        Ok(Self {
            discovery: config.validate_discovery(discovery)?,
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            keys: keys::signing_keys(jwks)?,
        })
    }
    pub fn verify(&self,encoded:&str,access_token:&str,expectation:IdTokenExpectation<'_>) -> Result<VerifiedLogin,BrowserError> {
        let invalid = BrowserError::Unauthenticated;
        if encoded.len() > 16384 || access_token.is_empty() || access_token.len() > 4096
            || !access_token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(invalid);
        }
        let parts: Vec<_> = encoded.split('.').take(4).collect();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) || parts[0].len() > 4096 {
            return Err(invalid);
        }
        // This untrusted header selects only among prevalidated public keys.
        // No claim is interpreted before the library verifies the signature.
        let raw_header = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid)?;
        let header = crate::contract_json::parse_unique_json(&raw_header).map_err(|_| invalid)?;
        let object = header.as_object().ok_or(invalid)?;
        if object.keys().any(|name| !matches!(name.as_str(), "alg" | "kid" | "typ"))
            || header.get("alg").and_then(serde_json::Value::as_str) != Some("RS256")
            || header.get("typ").is_some_and(|value| value.as_str() != Some("JWT")) {
            return Err(invalid);
        }
        let kid = header.get("kid").and_then(serde_json::Value::as_str).ok_or(invalid)?;
        let key = self.keys.get(kid).ok_or(invalid)?;
        let token = openid::IdToken::<Vec<u8>>::new_encoded(encoded)
            .decode(&key.jws_public_key_secret(), SignatureAlgorithm::RS256)
            .map_err(|_| invalid)?;
        let payload = token.payload().map_err(|_| invalid)?;
        claims::verify(self, payload, access_token, expectation)
    }
}

impl std::fmt::Debug for IdTokenVerifier {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("IdTokenVerifier([REDACTED])") }
}
impl std::fmt::Debug for VerifiedLogin {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("VerifiedLogin([REDACTED])") }
}

#[cfg(test)]
mod tests;
