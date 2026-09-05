//! Same-origin HTTP application. The listener must remain on a confined local
//! hop behind the configured HTTPS edge; this router does not terminate TLS.
use super::security::ConfiguredOrigin;
use super::{
    crypto::TokenKeyring, errors::BrowserError, oidc::OidcProvider, rpc::ManagementBridge,
    sessions::BrowserSessionStore,
};
use crate::{ExactScope, OperatorCredentialResolver};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
mod budget;
mod login;
mod refresh;
mod routing;
mod session;

pub struct BrowserConfig {
    pub session_max_age_secs: u32,
    pub idle_timeout_secs: u32,
    pub max_in_flight: usize,
    pub request_timeout: Duration,
}

pub struct BrowserDependencies {
    pub telemetry: super::telemetry::BrowserTelemetry,
    pub sessions: BrowserSessionStore,
    pub keys: Arc<TokenKeyring>,
    pub provider: Arc<OidcProvider>,
    pub management: ManagementBridge,
    pub resolver: Arc<dyn OperatorCredentialResolver>,
    pub global_scope_catalog: Vec<ExactScope>,
}

pub struct BrowserEdge {
    state: Arc<BrowserState>,
}
struct BrowserState {
    config: BrowserConfig,
    dependencies: BrowserDependencies,
    origin: ConfiguredOrigin,
    slots: Semaphore,
}
impl BrowserEdge {
    pub fn new(
        config: BrowserConfig,
        dependencies: BrowserDependencies,
    ) -> Result<Self, BrowserError> {
        if !(300..=86400).contains(&config.session_max_age_secs)
            || !(60..=3600).contains(&config.idle_timeout_secs)
            || config.idle_timeout_secs > config.session_max_age_secs
            || !(1..=256).contains(&config.max_in_flight)
            || !(Duration::from_secs(15)..=Duration::from_secs(60))
                .contains(&config.request_timeout)
            || dependencies.global_scope_catalog.len() > 256
        {
            return Err(BrowserError::Unavailable);
        }
        let origin = ConfiguredOrigin::parse(&dependencies.provider.config().public_origin)
            .map_err(|_| BrowserError::Unavailable)?;
        let slots = Semaphore::new(config.max_in_flight);
        Ok(Self {
            state: Arc::new(BrowserState {
                config,
                dependencies,
                origin,
                slots,
            }),
        })
    }
    pub fn router(self) -> axum::Router {
        routing::router(self.state)
    }
}
