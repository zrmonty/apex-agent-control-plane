use super::*;
use oauth2::{
    AuthType, AuthUrl, Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet, RedirectUrl,
    RequestTokenError, RevocationUrl, StandardRevocableToken, StandardTokenResponse, TokenUrl,
    basic::{
        BasicErrorResponse, BasicErrorResponseType, BasicRevocationErrorResponse,
        BasicTokenIntrospectionResponse, BasicTokenType,
    },
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub(super) struct ExtraFields {
    #[serde(default, deserialize_with = "present_id_token")]
    id_token: Option<String>,
    refresh_expires_in: Option<u64>,
}
// Only an absent field selects the optional no-ID refresh path. A present
// value must deserialize as a string; null and other JSON types are malformed.
fn present_id_token<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
impl oauth2::ExtraTokenFields for ExtraFields {}
impl std::fmt::Debug for ExtraFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtraFields([REDACTED])")
    }
}
impl Drop for ExtraFields {
    fn drop(&mut self) {
        if let Some(token) = self.id_token.as_mut() {
            token.zeroize();
        }
    }
}
type Response = StandardTokenResponse<ExtraFields, BasicTokenType>;
pub(super) type OAuthClient = Client<
    BasicErrorResponse,
    Response,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

pub(super) fn build_client(config: &OidcConfig) -> Result<OAuthClient, BrowserError> {
    config.validate()?;
    let invalid = BrowserError::Unavailable;
    Ok(Client::new(ClientId::new(config.client_id.clone()))
        .set_client_secret(ClientSecret::new(config.client_secret.to_string()))
        .set_auth_type(AuthType::BasicAuth)
        .set_auth_uri(AuthUrl::new(config.authorization_endpoint.clone()).map_err(|_| invalid)?)
        .set_token_uri(TokenUrl::new(config.token_endpoint.clone()).map_err(|_| invalid)?)
        .set_revocation_url(
            RevocationUrl::new(config.revocation_endpoint.clone()).map_err(|_| invalid)?,
        )
        .set_redirect_uri(RedirectUrl::from_url(config.callback_uri()?)))
}

pub(super) fn checked_material(
    response: &Response,
    old_refresh: Option<&str>,
    require_id: bool,
) -> Result<TokenMaterial, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    if response.token_type() != &BasicTokenType::Bearer {
        return Err(invalid);
    }
    let access = response.access_token().secret();
    let refresh = response.refresh_token().ok_or(invalid)?.secret();
    check_secret(access, 4096)?;
    check_secret(refresh, 4096)?;
    if old_refresh.is_some_and(|old| bool::from(old.as_bytes().ct_eq(refresh.as_bytes()))) {
        return Err(invalid);
    }
    let access_lifetime = response.expires_in().ok_or(invalid)?.as_secs();
    let refresh_lifetime = response.extra_fields().refresh_expires_in.ok_or(invalid)?;
    if !(1..=3600).contains(&access_lifetime) || !(1..=86400).contains(&refresh_lifetime) {
        return Err(invalid);
    }
    if let Some(scopes) = response.scopes()
        && (scopes.len() > 64
            || scopes
                .iter()
                .any(|scope| scope.as_str() == "offline_access" || scope.as_str().len() > 256)
            || !scopes.iter().any(|scope| scope.as_str() == "openid"))
    {
        return Err(invalid);
    }
    let id_token = response.extra_fields().id_token.as_deref();
    if require_id && id_token.is_none() {
        return Err(invalid);
    }
    if let Some(id_token) = id_token {
        check_secret(id_token, 16384)?;
    }
    Ok(TokenMaterial {
        access: Zeroizing::new(access.to_owned()),
        refresh: Zeroizing::new(refresh.to_owned()),
        id_token: id_token.map(|token| Zeroizing::new(token.to_owned())),
        access_lifetime,
        refresh_lifetime,
    })
}

pub(super) fn check_secret(value: &str, limit: usize) -> Result<(), BrowserError> {
    if value.is_empty() || value.len() > limit || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(BrowserError::Unauthenticated);
    }
    Ok(())
}

pub(super) fn exchange_error(
    error: RequestTokenError<BrowserError, BasicErrorResponse>,
) -> BrowserError {
    match error {
        RequestTokenError::Request(error) => error,
        RequestTokenError::ServerResponse(error)
            if error.error() == &BasicErrorResponseType::InvalidGrant =>
        {
            BrowserError::Unauthenticated
        }
        RequestTokenError::Parse(_, mut body) => {
            body.zeroize();
            BrowserError::Unavailable
        }
        // Never format the provider's error description, body or URL.
        _ => BrowserError::Unavailable,
    }
}
