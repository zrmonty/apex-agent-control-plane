//! Maintained OAuth2 request/response handling; no browser-facing provider tokens.
use super::config::OidcConfig;
use crate::browser::{errors::BrowserError, security::OpaqueToken};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, Scope,
    TokenResponse,
};
use oauth2::{HttpRequest, HttpResponse};
use std::future::Future;
use zeroize::Zeroizing;
mod response;
use response::{OAuthClient, build_client, checked_material, exchange_error};

pub(super) trait ProviderHttp: Send + Sync {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, BrowserError>> + Send;
}

// An explicit adapter preserves a Send future across OAuth2's higher-ranked
// client lifetime. A closure over the generic provider loses that guarantee
// when the enclosing exchange is spawned by the HTTP runtime.
struct HttpAdapter<'a, H>(&'a H);
impl<'c, H: ProviderHttp + 'c> oauth2::AsyncHttpClient<'c> for HttpAdapter<'_, H> {
    type Error = BrowserError;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, BrowserError>> + Send + 'c>>;
    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.0.send(request))
    }
}

pub struct AuthorizationChallenge {
    pub url: url::Url,
    pub state: OpaqueToken,
    pub nonce: OpaqueToken,
    pub pkce: OpaqueToken,
}
impl AuthorizationChallenge {
    pub fn new(config: &OidcConfig) -> Result<Self, BrowserError> {
        let client = build_client(config)?;
        let state = OpaqueToken::generate().map_err(|_| BrowserError::Unavailable)?;
        let nonce = OpaqueToken::generate().map_err(|_| BrowserError::Unavailable)?;
        let pkce = OpaqueToken::generate().map_err(|_| BrowserError::Unavailable)?;
        let verifier = PkceCodeVerifier::new(pkce.expose_secret().to_owned());
        let (url, _) = client
            .authorize_url(|| CsrfToken::new(state.expose_secret().to_owned()))
            .add_scope(Scope::new("openid".into()))
            .add_extra_param("nonce", nonce.expose_secret())
            .set_pkce_challenge(PkceCodeChallenge::from_code_verifier_sha256(&verifier))
            .url();
        Ok(Self {
            url,
            state,
            nonce,
            pkce,
        })
    }
}

pub(super) enum TokenRequest<'a> {
    Code { code: &'a str, pkce: &'a str },
    Refresh { token: &'a str },
}
pub(super) struct TokenMaterial {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub id_token: Option<Zeroizing<String>>,
    pub access_lifetime: u64,
    pub refresh_lifetime: u64,
}
pub(super) struct ProtocolClient {
    client: OAuthClient,
}
impl ProtocolClient {
    pub fn new(config: &OidcConfig) -> Result<Self, BrowserError> {
        Ok(Self {
            client: build_client(config)?,
        })
    }
    pub async fn exchange(
        &self,
        request: TokenRequest<'_>,
        http: &impl ProviderHttp,
    ) -> Result<TokenMaterial, BrowserError> {
        let transport = HttpAdapter(http);
        let (response, old_refresh, require_id) = match request {
            TokenRequest::Code { code, pkce } => {
                response::check_secret(code, 2048)?;
                OpaqueToken::parse(pkce).map_err(|_| BrowserError::Unauthenticated)?;
                let response = self
                    .client
                    .exchange_code(AuthorizationCode::new(code.to_owned()))
                    .set_pkce_verifier(PkceCodeVerifier::new(pkce.to_owned()))
                    .request_async(&transport)
                    .await
                    .map_err(exchange_error)?;
                (response, None, true)
            }
            TokenRequest::Refresh { token } => {
                response::check_secret(token, 4096)?;
                let refresh = RefreshToken::new(token.to_owned());
                let response = self
                    .client
                    .exchange_refresh_token(&refresh)
                    .request_async(&transport)
                    .await
                    .map_err(exchange_error)?;
                (response, Some(token), false)
            }
        };
        checked_material(&response, old_refresh, require_id)
    }
    pub async fn revoke(
        &self,
        refresh: &str,
        http: &impl ProviderHttp,
    ) -> Result<(), BrowserError> {
        response::check_secret(refresh, 4096)?;
        let transport = HttpAdapter(http);
        self.client
            .revoke_token(RefreshToken::new(refresh.to_owned()).into())
            .map_err(|_| BrowserError::Unavailable)?
            .request_async(&transport)
            .await
            .map_err(|_| BrowserError::Unavailable)
    }
}
macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(impl std::fmt::Debug for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
    })+};
}
redacted_debug!(AuthorizationChallenge, TokenMaterial, ProtocolClient);

#[cfg(test)]
mod tests;
