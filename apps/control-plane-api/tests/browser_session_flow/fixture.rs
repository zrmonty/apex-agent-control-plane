use super::{database, peer, support};
use apex_control_plane_api::{
    OperatorCredentialResolver,
    browser::{
        bundle::{LoginBinding, LoginBundle, SessionBundle},
        crypto::{TokenKey, TokenKeyring},
        edge::{BrowserConfig, BrowserDependencies, BrowserEdge},
        oidc::{OidcProvider, config::OidcConfig},
        security::{CsrfToken, OpaqueToken},
        sessions::{BrowserSessionStore, NewSession, SessionIdentity},
        telemetry::{BrowserTelemetry, ExportOwner},
    },
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

pub struct Fixture {
    pub database: database::Database,
    pub sessions: BrowserSessionStore,
    pub runtime: tokio::runtime::Runtime,
}
impl Fixture {
    pub fn new() -> Self {
        let database = database::Database::new();
        let sessions = BrowserSessionStore::connect(&database.url).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        Self {
            database,
            sessions,
            runtime,
        }
    }
}

pub struct Http {
    pub sessions: BrowserSessionStore,
    pub keys: Arc<TokenKeyring>,
    pub config: OidcConfig,
    pub peer: peer::Peer,
    pub client: reqwest::Client,
    pub origin: String,
    stop: tokio::sync::oneshot::Sender<()>,
    server: support::TestTask<()>,
    _export_owner: Option<ExportOwner>,
}
impl Http {
    pub async fn start(sessions: BrowserSessionStore) -> Self {
        let (telemetry, owner) = BrowserTelemetry::with_writer(std::io::sink()).unwrap();
        let mut http = Self::start_with_telemetry(sessions, telemetry).await;
        http._export_owner = Some(owner);
        http
    }
    pub async fn start_with_telemetry(
        sessions: BrowserSessionStore,
        telemetry: BrowserTelemetry,
    ) -> Self {
        let pki = support::Pki::require();
        let peer = peer::Peer::start(&pki, peer::Mode::Real).await;
        let config = super::provider_config(&pki);
        let resolver: Arc<dyn OperatorCredentialResolver> = Arc::new(support::resolver());
        let provider = Arc::new(
            OidcProvider::new(super::provider_config(&pki), Arc::clone(&resolver)).unwrap(),
        );
        let keys = Arc::new(
            TokenKeyring::new(vec![
                TokenKey::active("fixture", Zeroizing::new([8; 32])).unwrap(),
            ])
            .unwrap(),
        );
        let edge = BrowserEdge::new(
            BrowserConfig {
                session_max_age_secs: 28800,
                idle_timeout_secs: 900,
                max_in_flight: 16,
                request_timeout: Duration::from_secs(30),
            },
            BrowserDependencies {
                telemetry,
                sessions: sessions.clone(),
                keys: Arc::clone(&keys),
                provider,
                management: support::connect(&pki, &peer.target, support::RPC_TIMEOUT).await,
                resolver,
                global_scope_catalog: Vec::new(),
            },
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopping) = tokio::sync::oneshot::channel();
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
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        Self {
            sessions,
            keys,
            config,
            peer,
            client,
            origin,
            stop,
            server,
            _export_owner: None,
        }
    }

    // Explicitly seeds already-verified credentials: this exercises the HTTP/PG/
    // mTLS composition, not provider login or production JWT verification.
    pub async fn seed(&self, subject: &str, access: &str) -> (OpaqueToken, CsrfToken) {
        self.seed_with_lifetime(subject, access, 300).await
    }
    pub async fn seed_with_lifetime(
        &self,
        subject: &str,
        access: &str,
        access_lifetime: i64,
    ) -> (OpaqueToken, CsrfToken) {
        let token = OpaqueToken::generate().unwrap();
        let csrf = CsrfToken::generate().unwrap();
        let now = now();
        let identity = SessionIdentity {
            digest: token.lookup_digest(),
            issuer: self.config.issuer.clone(),
            client_id: self.config.client_id.clone(),
            subject: subject.into(),
            absolute_expires_at: now + 3600,
        };
        let bundle = SessionBundle {
            access: Zeroizing::new(access.into()),
            refresh: Zeroizing::new("fixture-refresh-secret-canary".into()),
            nonce: OpaqueToken::generate().unwrap(),
            csrf: CsrfToken::parse(csrf.expose_secret()).unwrap(),
            generation: 0,
            access_expires_at: now + access_lifetime,
            refresh_expires_at: now + 3600,
        };
        self.sessions
            .create_session(NewSession {
                envelope: bundle.seal(&identity, &self.keys, now).unwrap(),
                identity,
                csrf_binding: csrf.binding(),
                access_expires_at: bundle.access_expires_at,
                refresh_expires_at: bundle.refresh_expires_at,
                idle_timeout_secs: 900,
            })
            .await
            .unwrap();
        (token, csrf)
    }

    pub fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &OpaqueToken,
    ) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.origin))
            .header(
                "cookie",
                format!("__Host-apex_session={}", token.expose_secret()),
            )
            .header("authorization", "Bearer hostile-browser-secret-canary")
    }
    pub async fn seed_login(&self) -> (OpaqueToken, OpaqueToken) {
        let state = OpaqueToken::generate().unwrap();
        let browser = OpaqueToken::generate().unwrap();
        let now = now();
        let bundle = LoginBundle {
            pkce: OpaqueToken::generate().unwrap(),
            nonce: OpaqueToken::generate().unwrap(),
        };
        let row = bundle
            .seal(
                &LoginBinding {
                    state: state.lookup_digest(),
                    browser: browser.lookup_digest(),
                    expires_at: now + 599,
                },
                &self.config,
                &self.keys,
                now,
            )
            .unwrap();
        self.sessions.create_login(row).await.unwrap();
        (state, browser)
    }
    pub async fn shutdown(self) {
        let _ = self.stop.send(());
        self.server.join().await;
        self.peer.shutdown().await;
        self.sessions.shutdown().await.unwrap();
    }
}
