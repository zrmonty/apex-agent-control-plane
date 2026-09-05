//! Owned BFF/management listeners with actual Keycloak authorization throughout.
use super::{database, gate::RefreshGate, support};
use apex_control_plane_api::{
    CommandError, InMemoryProxyStore, KeycloakConfig, KeycloakOperatorCredentialResolver,
    McpProxyService, OperatorCaller, OperatorCredentialResolver, OperatorTokenAuthenticator,
    bounded_mcp_proxy_service_server,
    browser::{
        crypto::{TokenKey, TokenKeyring},
        edge::{BrowserConfig, BrowserDependencies, BrowserEdge},
        oidc::{OidcProvider, config::OidcConfig},
        sessions::BrowserSessionStore,
    },
};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tonic::{
    service::interceptor::InterceptedService,
    transport::{Certificate, Identity, Server, ServerTlsConfig, server::TcpIncoming},
};
use zeroize::Zeroizing;

pub const WATCHDOG: Duration = Duration::from_secs(2);

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WATCHDOG, future)
        .await
        .expect("E2 handshake exceeded its two-second watchdog")
}

pub struct Fixture {
    pub sessions: BrowserSessionStore,
    pub runtime: tokio::runtime::Runtime,
    pub resolver: Arc<dyn OperatorCredentialResolver>,
    pub database: database::Database,
    pub config: OidcConfig,
    pub pki: support::Pki,
    // Last to drop: the resolver's synchronous startup/refresher needs this
    // independent runtime even when the BFF's current-thread runtime is idle.
    pub gate: RefreshGate,
}

#[derive(Clone)]
struct SharedResolver(Arc<dyn OperatorCredentialResolver>);
impl OperatorCredentialResolver for SharedResolver {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError> {
        self.0.resolve(token)
    }
}

impl Fixture {
    pub fn new() -> Self {
        let issuer = std::env::var("APEX_BROWSER_REFRESH_TEST_ISSUER")
            .expect("APEX_BROWSER_REFRESH_TEST_ISSUER requires the second real Keycloak fixture advertising HTTPS port 18461");
        assert_eq!(issuer, super::gate::ISSUER);
        let pki = support::Pki::require();
        let gate = RefreshGate::start(&pki);
        // Gate::start acknowledges a listening, actively polled OS-thread
        // runtime BEFORE this blocking production resolver fetches real JWKS.
        let resolver: Arc<dyn OperatorCredentialResolver> = Arc::new(
            KeycloakOperatorCredentialResolver::start(KeycloakConfig {
                issuer: issuer.clone(),
                audience: "apex-control-gateway".into(),
                jwks_url: KeycloakConfig::default_jwks_url(&issuer),
                jwks_ca_pem: pki.trusted("ca.pem"),
                jwks_refresh: Duration::from_secs(30),
                jwks_max_age: Duration::from_secs(120),
                scope_claim: "apex_control_scopes".into(),
                role_claim: "realm_access.roles".into(),
                global_role: None,
                global_subjects: Default::default(),
                max_token_lifetime: Duration::from_secs(3600),
                expected_typ: Some("Bearer".into()),
            })
            .unwrap(),
        );
        let realm: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../deploy/compose/gateway-ref/keycloak/apex-realm.json"
        ))
        .unwrap();
        let client = realm["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["clientId"] == "apex-browser")
            .unwrap();
        let config = OidcConfig {
            issuer: issuer.clone(),
            client_id: "apex-browser".into(),
            client_secret: Zeroizing::new(client["secret"].as_str().unwrap().into()),
            public_origin: "https://console.example".into(),
            provider_ca_pem: pki.trusted("ca.pem"),
            authorization_endpoint: format!("{issuer}/protocol/openid-connect/auth"),
            token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
            jwks_uri: KeycloakConfig::default_jwks_url(&issuer),
            revocation_endpoint: format!("{issuer}/protocol/openid-connect/revoke"),
        };
        let database = database::Database::new();
        let sessions = BrowserSessionStore::connect(&database.url).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        Self {
            sessions,
            runtime,
            resolver,
            database,
            config,
            pki,
            gate,
        }
    }

    pub async fn start(&self) -> Http {
        let service = McpProxyService::from_store(
            OperatorTokenAuthenticator::new(SharedResolver(Arc::clone(&self.resolver))),
            Arc::new(InMemoryProxyStore::default()),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        // Observes arrival only; authorization still runs in the real service.
        let service = InterceptedService::new(
            bounded_mcp_proxy_service_server(service),
            move |request: tonic::Request<()>| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(request)
            },
        );
        let key = Zeroizing::new(self.pki.trusted("control-plane-server.key"));
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.pki.trusted("control-plane-server.pem"),
                key.as_slice(),
            ))
            .client_ca_root(Certificate::from_pem(self.pki.trusted("ca.pem")))
            .client_auth_optional(false);
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = format!("https://{}", incoming.local_addr().unwrap());
        let (stop_rpc, stopping) = tokio::sync::oneshot::channel();
        let rpc = support::TestTask::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let keys = Arc::new(
            TokenKeyring::new(vec![
                TokenKey::active("fixture", Zeroizing::new([9; 32])).unwrap(),
            ])
            .unwrap(),
        );
        let config = &self.config;
        let provider = Arc::new(
            OidcProvider::new(
                OidcConfig {
                    issuer: config.issuer.clone(),
                    client_id: config.client_id.clone(),
                    client_secret: config.client_secret.clone(),
                    public_origin: config.public_origin.clone(),
                    provider_ca_pem: config.provider_ca_pem.clone(),
                    authorization_endpoint: config.authorization_endpoint.clone(),
                    token_endpoint: config.token_endpoint.clone(),
                    jwks_uri: config.jwks_uri.clone(),
                    revocation_endpoint: config.revocation_endpoint.clone(),
                },
                Arc::clone(&self.resolver),
            )
            .unwrap(),
        );
        let (telemetry, export_owner) =
            apex_control_plane_api::browser::telemetry::BrowserTelemetry::with_writer(
                std::io::sink(),
            )
            .unwrap();
        let edge = BrowserEdge::new(
            BrowserConfig {
                session_max_age_secs: 3600,
                idle_timeout_secs: 900,
                max_in_flight: 16,
                request_timeout: Duration::from_secs(30),
            },
            BrowserDependencies {
                telemetry,
                sessions: self.sessions.clone(),
                keys: Arc::clone(&keys),
                provider,
                management: support::connect(&self.pki, &target, Duration::from_secs(2)).await,
                resolver: Arc::clone(&self.resolver),
                global_scope_catalog: vec![],
            },
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop_http, stopping) = tokio::sync::oneshot::channel();
        let server = support::TestTask::spawn(async move {
            axum::serve(listener, edge.router())
                .with_graceful_shutdown(async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        Http {
            _export_owner: export_owner,
            origin,
            client,
            keys,
            calls,
            stop_http,
            stop_rpc,
            server,
            rpc,
        }
    }
}

pub struct Http {
    _export_owner: apex_control_plane_api::browser::telemetry::ExportOwner,
    pub origin: String,
    pub client: reqwest::Client,
    pub keys: Arc<TokenKeyring>,
    calls: Arc<AtomicUsize>,
    stop_http: tokio::sync::oneshot::Sender<()>,
    stop_rpc: tokio::sync::oneshot::Sender<()>,
    server: support::TestTask<()>,
    rpc: support::TestTask<()>,
}

impl Http {
    pub fn management_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub async fn shutdown(self) {
        let _ = self.stop_http.send(());
        self.server.join().await;
        let _ = self.stop_rpc.send(());
        self.rpc.join().await;
    }
}
