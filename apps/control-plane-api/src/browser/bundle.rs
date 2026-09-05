//! Protected storage payloads, separate from OIDC verification and authority.
//! Only verified provider results may be assembled into a new session bundle.
use super::crypto::{EnvelopePurpose, RecordDigest, TokenBinding};
use super::{
    crypto::{TokenEnvelope, TokenKeyring},
    errors::BrowserError,
    oidc::config::OidcConfig,
    security::{CsrfToken, LookupDigest, OpaqueToken},
    sessions::{NewLoginAttempt, SessionIdentity, StoredSession},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
mod codec;
use codec::Reader;

pub struct LoginBinding {
    pub state: LookupDigest,
    pub browser: LookupDigest,
    pub expires_at: i64,
}
pub struct LoginBundle {
    pub pkce: OpaqueToken,
    pub nonce: OpaqueToken,
}
impl LoginBundle {
    pub fn seal(
        &self,
        binding: &LoginBinding,
        config: &OidcConfig,
        keys: &TokenKeyring,
        now: i64,
    ) -> Result<NewLoginAttempt, BrowserError> {
        config.validate()?;
        codec::remaining(binding.expires_at, now, 600)?;
        let context = login_context(
            binding.state,
            &config.issuer,
            &config.client_id,
            binding.expires_at,
        )?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(119));
        bytes.push(1);
        bytes.extend_from_slice(binding.browser.as_bytes());
        bytes.extend_from_slice(self.pkce.expose_secret().as_bytes());
        bytes.extend_from_slice(self.nonce.expose_secret().as_bytes());
        let envelope = keys
            .seal(&bytes, &context, now)
            .map_err(|_| BrowserError::Unavailable)?;
        Ok(NewLoginAttempt {
            state: binding.state,
            browser: binding.browser,
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            expires_at: binding.expires_at,
            envelope,
        })
    }
    pub fn open(
        row: &NewLoginAttempt,
        config: &OidcConfig,
        keys: &TokenKeyring,
        now: i64,
    ) -> Result<Self, BrowserError> {
        let invalid = BrowserError::Unauthenticated;
        if row.issuer != config.issuer || row.client_id != config.client_id {
            return Err(invalid);
        }
        let context = login_context(row.state, &row.issuer, &row.client_id, row.expires_at)?;
        let bytes = keys
            .open(&row.envelope, &context, now)
            .map_err(|_| invalid)?;
        let mut reader = Reader::new(bytes.expose_bytes());
        reader.version()?;
        if !bool::from(reader.take(32)?.ct_eq(row.browser.as_bytes())) {
            return Err(invalid);
        }
        let pkce = OpaqueToken::parse(reader.text(43)?).map_err(|_| invalid)?;
        let nonce = OpaqueToken::parse(reader.text(43)?).map_err(|_| invalid)?;
        reader.finish()?;
        Ok(Self { pkce, nonce })
    }
}

fn login_context<'a>(
    state: LookupDigest,
    issuer: &'a str,
    client_id: &'a str,
    expires_at: i64,
) -> Result<TokenBinding<'a>, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    TokenBinding::new(
        EnvelopePurpose::LoginAttempt,
        RecordDigest::from_sha256(state.as_bytes()).map_err(|_| invalid)?,
        issuer,
        client_id,
        None,
        expires_at,
    )
    .map_err(|_| invalid)
}

pub struct SessionBundle {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub nonce: OpaqueToken,
    pub csrf: CsrfToken,
    pub generation: u64,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}
impl SessionBundle {
    pub fn seal(
        &self,
        identity: &SessionIdentity,
        keys: &TokenKeyring,
        now: i64,
    ) -> Result<TokenEnvelope, BrowserError> {
        codec::remaining(identity.absolute_expires_at, now, 86400)?;
        codec::remaining(self.access_expires_at, now, 3600)?;
        codec::remaining(self.refresh_expires_at, now, 86400)?;
        if self.generation > i64::MAX as u64 {
            return Err(BrowserError::Unavailable);
        }
        let bytes = codec::encode(self)?;
        keys.seal(&bytes, &identity.token_binding()?, now)
            .map_err(|_| BrowserError::Unavailable)
    }
    pub fn open(
        row: &StoredSession,
        config: &OidcConfig,
        keys: &TokenKeyring,
        now: i64,
    ) -> Result<Self, BrowserError> {
        let invalid = BrowserError::Unauthenticated;
        if row.identity.issuer != config.issuer
            || row.identity.client_id != config.client_id
            || row.idle_expires_at <= now
            || row.idle_expires_at > row.identity.absolute_expires_at
            || row.refresh_expires_at <= now
        {
            return Err(invalid);
        }
        let expected_generation = if let Some(deadline) = row.refresh_deadline {
            if deadline <= now
                || deadline > row.idle_expires_at
                || deadline > row.refresh_expires_at
            {
                return Err(invalid);
            }
            row.generation.checked_sub(1).ok_or(invalid)?
        } else {
            row.generation
        };
        let bytes = keys
            .open(&row.envelope, &row.identity.token_binding()?, now)
            .map_err(|_| invalid)?;
        let payload = codec::decode(bytes.expose_bytes())?;
        if payload.generation != expected_generation
            || payload.access_expires_at != row.access_expires_at
            || payload.refresh_expires_at != row.refresh_expires_at
            || !bool::from(
                payload
                    .csrf
                    .binding()
                    .as_bytes()
                    .ct_eq(row.csrf_binding.as_bytes()),
            )
        {
            return Err(invalid);
        }
        Ok(payload)
    }
}
macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(impl std::fmt::Debug for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
    })+};
}
redacted_debug!(LoginBinding, LoginBundle, SessionBundle);
#[cfg(test)]
mod tests;
