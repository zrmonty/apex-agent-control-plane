use super::{database, support};
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
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig, server::TcpIncoming};
use zeroize::Zeroizing;

pub struct Fixture {
    pub database: database::Database,
    pub sessions: BrowserSessionStore,
    pub runtime: tokio::runtime::Runtime,
    pub issuer: String,
    pub pki: support::Pki,
    resolver: Arc<dyn OperatorCredentialResolver>,
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
        let issuer = std::env::var("APEX_BROWSER_KEYCLOAK_ISSUER")
            .expect("required owned real HTTPS Keycloak fixture: APEX_BROWSER_KEYCLOAK_ISSUER");
        let parsed = url::Url::parse(&issuer).unwrap();
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        assert_eq!(parsed.path(), "/realms/apex");
        assert!(
            parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.username().is_empty()
                && parsed.password().is_none()
        );
        let database = database::Database::new();
        let sessions = BrowserSessionStore::connect(&database.url).unwrap();
        let pki = support::Pki::require();
        // Real production resolver performs its initial JWKS HTTPS fetch and
        // owns its cache/refresher. Construction is outside the Tokio runtime.
        let resolver = Arc::new(
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        Self {
            database,
            sessions,
            runtime,
            issuer,
            pki,
            resolver,
        }
    }
    pub fn config(&self) -> OidcConfig {
        let realm: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../deploy/compose/gateway-ref/keycloak/apex-realm.json"
        ))
        .unwrap();
        let client = realm["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["clientId"] == "apex-browser")
            .expect("lab realm must configure the browser client");
        OidcConfig {
            issuer: self.issuer.clone(),
            client_id: "apex-browser".into(),
            client_secret: Zeroizing::new(client["secret"].as_str().unwrap().into()),
            public_origin: "https://console.example".into(),
            provider_ca_pem: self.pki.trusted("ca.pem"),
            authorization_endpoint: format!("{}/protocol/openid-connect/auth", self.issuer),
            token_endpoint: format!("{}/protocol/openid-connect/token", self.issuer),
            jwks_uri: KeycloakConfig::default_jwks_url(&self.issuer),
            revocation_endpoint: format!("{}/protocol/openid-connect/revoke", self.issuer),
        }
    }
    pub async fn start(&self) -> Http {
        let service = McpProxyService::from_store(
            OperatorTokenAuthenticator::new(SharedResolver(Arc::clone(&self.resolver))),
            Arc::new(InMemoryProxyStore::default()),
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
                .add_service(bounded_mcp_proxy_service_server(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopping.await;
                })
                .await
                .unwrap();
        });
        let provider =
            Arc::new(OidcProvider::new(self.config(), Arc::clone(&self.resolver)).unwrap());
        let keys = Arc::new(
            TokenKeyring::new(vec![
                TokenKey::active("fixture", Zeroizing::new([9; 32])).unwrap(),
            ])
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
                provider: Arc::clone(&provider),
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
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        Http {
            _export_owner: export_owner,
            origin,
            client,
            keys,
            provider,
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
    pub provider: Arc<OidcProvider>,
    stop_http: tokio::sync::oneshot::Sender<()>,
    stop_rpc: tokio::sync::oneshot::Sender<()>,
    server: support::TestTask<()>,
    rpc: support::TestTask<()>,
}
impl Http {
    pub async fn shutdown(self) {
        let _ = self.stop_http.send(());
        self.server.join().await;
        let _ = self.stop_rpc.send(());
        self.rpc.join().await;
    }
}
