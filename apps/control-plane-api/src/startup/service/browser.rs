//! Startup-owned browser configuration and listener lifecycle.
mod config;
mod material;
pub(super) mod observations;
use crate::startup::{
    env::{self, BrowserEnv, OperatorTokenSource},
    secrets,
};
use apex_control_plane_api::{
    ExactScope, OperatorCredentialResolver,
    browser::{
        crypto::{TokenKey, TokenKeyring},
        edge::{BrowserConfig, BrowserDependencies, BrowserEdge},
        oidc::{OidcProvider, config::OidcConfig},
        rpc::{ManagementBridge, ManagementTransportConfig},
        sessions::BrowserSessionStore,
        telemetry::{BrowserTelemetry, ExportOwner},
    },
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

pub(super) struct PreparedBrowser {
    pub bind_addr: SocketAddr,
    pub transport: ManagementTransportConfig,
    pub sessions: BrowserSessionStore,
    pub exporter: Option<ExportOwner>,
    pub telemetry: BrowserTelemetry,
    edge: BrowserConfig,
    keys: Arc<TokenKeyring>,
    provider: Arc<OidcProvider>,
    resolver: Arc<dyn OperatorCredentialResolver>,
    catalog: Vec<ExactScope>,
}

pub(super) fn prepare(
    configured: Option<BrowserEnv>,
    base: &Path,
    control_bind: SocketAddr,
    resolver: Arc<dyn OperatorCredentialResolver>,
) -> Result<Option<PreparedBrowser>, io::Error> {
    let Some(configured) = configured else {
        return Ok(None);
    };
    let OperatorTokenSource::Keycloak(issuer) = env::operator_token_source()? else {
        return Err(config::invalid());
    };
    let keycloak = env::keycloak_env(issuer)?;
    let path = secrets::trusted_secret_path(
        &configured.config_file,
        base,
        config::MAX_CONFIG_BYTES as u64,
        false,
        "APEX_CONTROL_BROWSER_CONFIG_FILE",
    )?;
    let bytes = secrets::read_bounded(
        &path,
        config::MAX_CONFIG_BYTES,
        "APEX_CONTROL_BROWSER_CONFIG_FILE",
    )?;
    let settings =
        config::Settings::parse(&bytes, &keycloak.audience, keycloak.expected_typ.as_deref())?;
    if keycloak.max_token_lifetime > Duration::from_secs(3600) {
        return Err(config::invalid());
    }
    let edge = settings.edge_config();
    let catalog = settings.scope_catalog()?;
    let transport = ManagementTransportConfig {
        target: management_target(control_bind)?,
        server_name: settings.management.server_name,
        ca_pem: material::read_public(
            base,
            &settings.management.ca_file,
            1024 * 1024,
            "browser management CA",
        )?,
        client_certificate_pem: material::read_public(
            base,
            &settings.management.certificate_file,
            1024 * 1024,
            "browser management certificate",
        )?,
        client_key_pem: material::read_private(
            base,
            &settings.management.key_file,
            1024 * 1024,
            "browser management private key",
        )?,
        connect_timeout: Duration::from_secs(5),
        rpc_timeout: Duration::from_secs(10),
        max_in_flight: settings.max_in_flight,
    };
    transport.validate().map_err(|_| config::invalid())?;
    let oidc = OidcConfig {
        authorization_endpoint: format!("{}/protocol/openid-connect/auth", keycloak.issuer),
        token_endpoint: format!("{}/protocol/openid-connect/token", keycloak.issuer),
        revocation_endpoint: format!("{}/protocol/openid-connect/revoke", keycloak.issuer),
        jwks_uri: keycloak.jwks_url,
        issuer: keycloak.issuer,
        client_id: settings.client_id,
        public_origin: settings.public_origin,
        client_secret: material::client_secret(base, &settings.client_secret_file)?,
        provider_ca_pem: material::read_public(
            base,
            &keycloak.ca_file,
            1024 * 1024,
            "browser provider CA",
        )?,
    };
    let mut keys = Vec::with_capacity(settings.session_keys.len());
    for file in settings.session_keys {
        let key = match file {
            config::KeyFile::Active { id, file } => {
                TokenKey::active(&id, material::session_key(base, &file)?)
            }
            config::KeyFile::Retired {
                id,
                file,
                decrypt_until_unix_seconds,
            } => TokenKey::retired(
                &id,
                material::session_key(base, &file)?,
                decrypt_until_unix_seconds,
            ),
        }
        .map_err(|_| config::invalid())?;
        keys.push(key);
    }
    let keys = Arc::new(TokenKeyring::new(keys).map_err(|_| config::invalid())?);
    let provider =
        Arc::new(OidcProvider::new(oidc, Arc::clone(&resolver)).map_err(|_| config::invalid())?);
    // All config/private material is validated before creating browser storage.
    let database = env::control_postgres_url()?.ok_or_else(config::invalid)?;
    let (telemetry, exporter) = BrowserTelemetry::new()
        .map_err(|_| io::Error::other("browser observation initialization failed"))?;
    let sessions = BrowserSessionStore::connect(&database)
        .map_err(|_| io::Error::other("browser session storage unavailable"))?;
    Ok(Some(PreparedBrowser {
        bind_addr: configured.bind_addr,
        transport,
        sessions,
        telemetry,
        exporter: Some(exporter),
        edge,
        keys,
        provider,
        resolver,
        catalog,
    }))
}

impl PreparedBrowser {
    pub async fn serve(
        self,
        listener: tokio::net::TcpListener,
        shutdown: apex_control_plane_api::GatewayShutdown,
    ) -> Result<(), io::Error> {
        let Some(management) =
            connect_until_shutdown(&shutdown, ManagementBridge::connect(self.transport))
                .await
                .map_err(|_| io::Error::other("browser management mTLS connection unavailable"))?
        else {
            return Ok(());
        };
        let edge = BrowserEdge::new(
            self.edge,
            BrowserDependencies {
                telemetry: self.telemetry,
                sessions: self.sessions,
                keys: self.keys,
                provider: self.provider,
                management,
                resolver: self.resolver,
                global_scope_catalog: self.catalog,
            },
        )
        .map_err(|_| config::invalid())?;
        if shutdown.is_requested() {
            return Ok(());
        }
        axum::serve(listener, edge.router())
            .with_graceful_shutdown(async move {
                shutdown.wait().await;
            })
            .await
    }
}

async fn connect_until_shutdown<T, E>(
    shutdown: &apex_control_plane_api::GatewayShutdown,
    operation: impl std::future::Future<Output = Result<T, E>>,
) -> Result<Option<T>, E> {
    tokio::select! {
        biased;
        _ = shutdown.wait() => Ok(None),
        result = operation => {
            // Cancellation can arrive during the operation's final poll.
            // Original serving-task failures remain owned by the supervisor.
            if shutdown.is_requested() { Ok(None) } else { result.map(Some) }
        }
    }
}

#[cfg(test)]
#[path = "browser/connect_tests.rs"]
mod connect_tests;

fn management_target(control: SocketAddr) -> Result<String, io::Error> {
    if control.port() == 0 || (!control.ip().is_loopback() && !control.ip().is_unspecified()) {
        return Err(config::invalid());
    }
    let ip = match control.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(format!("https://{}", SocketAddr::new(ip, control.port())))
}
