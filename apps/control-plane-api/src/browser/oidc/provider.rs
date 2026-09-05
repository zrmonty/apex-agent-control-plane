//! One bounded, non-retrying provider exchange; durable one-use state and refresh
//! fencing are the caller's responsibility and must precede these operations.
use super::{
    AuthorizationChallenge,
    config::OidcConfig,
    http::BoundedProviderHttp,
    protocol::{ProtocolClient, ProviderHttp, TokenRequest},
    tokens::{VerifiedProviderTokens, unix_now, validate_exchange},
    verify::{IdTokenExpectation, IdTokenVerifier},
};
use crate::{OperatorCredentialResolver, browser::errors::BrowserError};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

trait ProviderSource: ProviderHttp {
    fn discovery(&self) -> impl Future<Output = Result<Vec<u8>, BrowserError>> + Send;
    fn jwks(&self) -> impl Future<Output = Result<Vec<u8>, BrowserError>> + Send;
}
impl ProviderSource for BoundedProviderHttp {
    async fn discovery(&self) -> Result<Vec<u8>, BrowserError> {
        self.discovery().await
    }
    async fn jwks(&self) -> Result<Vec<u8>, BrowserError> {
        self.jwks().await
    }
}

pub struct OidcProvider {
    core: ProviderCore<BoundedProviderHttp>,
}
trait MonotonicClock: Send + Sync {
    fn now(&self) -> Instant;
}
struct SystemClock;
impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct ProviderCore<H, C = SystemClock> {
    config: Arc<OidcConfig>,
    http: H,
    protocol: ProtocolClient,
    resolver: Arc<dyn OperatorCredentialResolver>,
    slots: Semaphore,
    clock: C,
}

impl OidcProvider {
    /// Startup must supply its configured Keycloak access-token authority, with
    /// a distinct API audience and the same literal issuer as this browser client.
    pub fn new(
        config: OidcConfig,
        resolver: Arc<dyn OperatorCredentialResolver>,
    ) -> Result<Self, BrowserError> {
        let http = BoundedProviderHttp::new(&config)?;
        Ok(Self {
            core: ProviderCore::new(Arc::new(config), http, resolver)?,
        })
    }
    pub fn config(&self) -> &OidcConfig {
        &self.core.config
    }
    pub async fn authorization_challenge(&self) -> Result<AuthorizationChallenge, BrowserError> {
        self.core.challenge().await
    }
    pub async fn login(
        &self,
        code: &str,
        pkce: &str,
        nonce: &str,
    ) -> Result<VerifiedProviderTokens, BrowserError> {
        self.core
            .exchange(
                TokenRequest::Code { code, pkce },
                IdTokenExpectation::Login { nonce },
            )
            .await
    }
    pub async fn refresh(
        &self,
        token: &str,
        subject: &str,
        nonce: &str,
    ) -> Result<VerifiedProviderTokens, BrowserError> {
        self.core
            .exchange(
                TokenRequest::Refresh { token },
                IdTokenExpectation::Refresh {
                    subject,
                    original_nonce: nonce,
                },
            )
            .await
    }
    /// Call only AFTER durable local revocation; provider failure cannot undo it.
    pub async fn revoke(&self, token: &str) -> Result<(), BrowserError> {
        self.core.revoke(token).await
    }
}
impl std::fmt::Debug for OidcProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcProvider([REDACTED])")
    }
}

impl<H: ProviderSource> ProviderCore<H> {
    fn new(
        config: Arc<OidcConfig>,
        http: H,
        resolver: Arc<dyn OperatorCredentialResolver>,
    ) -> Result<Self, BrowserError> {
        Self::with_clock(config, http, resolver, SystemClock)
    }
}
impl<H: ProviderSource, C: MonotonicClock> ProviderCore<H, C> {
    fn with_clock(
        config: Arc<OidcConfig>,
        http: H,
        resolver: Arc<dyn OperatorCredentialResolver>,
        clock: C,
    ) -> Result<Self, BrowserError> {
        let protocol = ProtocolClient::new(&config)?;
        Ok(Self {
            config,
            http,
            protocol,
            resolver,
            slots: Semaphore::new(8),
            clock,
        })
    }
    async fn challenge(&self) -> Result<AuthorizationChallenge, BrowserError> {
        self.bounded(|deadline| async move {
            let discovery = self.guarded(deadline, self.http.discovery()).await?;
            self.config.validate_discovery(&discovery)?;
            self.check_deadline(deadline)?;
            AuthorizationChallenge::new(&self.config)
        })
        .await
    }
    async fn exchange(
        &self,
        request: TokenRequest<'_>,
        expectation: IdTokenExpectation<'_>,
    ) -> Result<VerifiedProviderTokens, BrowserError> {
        self.bounded(|deadline| async move {
            let started_at = unix_now()?;
            let discovery = self.guarded(deadline, self.http.discovery()).await?;
            // Do not fetch the key endpoint until issuer, fixed URLs and protocol
            // capabilities in discovery have all matched deployment policy.
            self.config.validate_discovery(&discovery)?;
            let jwks = self.guarded(deadline, self.http.jwks()).await?;
            let verifier = IdTokenVerifier::new(&self.config, &discovery, &jwks)?;
            let material = self
                .guarded(deadline, self.protocol.exchange(request, &self.http))
                .await?;
            validate_exchange(
                &self.config,
                material,
                &verifier,
                self.resolver.as_ref(),
                expectation,
                started_at,
            )
        })
        .await
    }
    async fn revoke(&self, token: &str) -> Result<(), BrowserError> {
        self.bounded(|_| self.protocol.revoke(token, &self.http))
            .await
    }
    async fn bounded<T, F: Future<Output = Result<T, BrowserError>>>(
        &self,
        operation: impl FnOnce(Instant) -> F,
    ) -> Result<T, BrowserError> {
        let _permit = self
            .slots
            .try_acquire()
            .map_err(|_| BrowserError::RateLimited)?;
        let deadline = self
            .clock
            .now()
            .checked_add(Duration::from_secs(10))
            .ok_or(BrowserError::Unavailable)?;
        tokio::time::timeout_at(deadline.into(), self.guarded(deadline, operation(deadline)))
            .await
            .map_err(|_| BrowserError::Unavailable)?
    }
    fn check_deadline(&self, deadline: Instant) -> Result<(), BrowserError> {
        if self.clock.now() >= deadline {
            return Err(BrowserError::Unavailable);
        }
        Ok(())
    }
    async fn guarded<T>(
        &self,
        deadline: Instant,
        operation: impl Future<Output = Result<T, BrowserError>>,
    ) -> Result<T, BrowserError> {
        let mut operation = pin!(operation);
        poll_fn(|cx| {
            // timeout_at polls its inner future first. Guard both resumption
            // and completion; per-stage guards also stop same-poll transitions.
            if let Err(error) = self.check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            let result = operation.as_mut().poll(cx);
            if let Err(error) = self.check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            result
        })
        .await
    }
}

#[cfg(test)]
mod tests;
