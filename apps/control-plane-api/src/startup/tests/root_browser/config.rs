use super::{Case, pg, support};
use std::{net::TcpListener, path::PathBuf, process::Command};
use zeroize::Zeroizing;

pub(super) struct Fixture {
    // The child guard must be dropped before this fixture and its UUID schema.
    pub directory: support::OwnedDir,
    pub root_app: String,
    pub observer_url: String,
    pub root_url: String,
    pub proxy_id: String,
    pub control: std::net::SocketAddr,
    pub browser: std::net::SocketAddr,
    control_reservation: Option<TcpListener>,
    browser_reservation: Option<TcpListener>,
    config: PathBuf,
    pki_root: String,
    issuer: String,
}

impl Fixture {
    pub fn new(case: Case, schema_url: &str) -> Self {
        let issuer = support::required("APEX_BROWSER_KEYCLOAK_ISSUER");
        assert!(
            issuer == "https://127.0.0.1:18451/realms/apex",
            "expected owned Keycloak fixture"
        );
        let pki_root = support::required("APEX_BROWSER_TEST_PKI_DIR");
        let pki = support::Pki::require();
        let directory = support::OwnedDir::new();
        for name in [
            "ca.pem",
            "control-plane-server.pem",
            "control-plane-server.key",
            "control-operator-client.pem",
            "control-operator-client.key",
            "mcp-gateway-token",
        ] {
            let bytes = Zeroizing::new(pki.trusted(name));
            directory.write(name, &bytes);
        }
        let realm: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/gateway-ref/keycloak/apex-realm.json"
        )))
        .unwrap();
        let clients: Vec<_> = realm["clients"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|client| client["clientId"] == "apex-browser")
            .collect();
        assert_eq!(clients.len(), 1);
        let secret = Zeroizing::new(clients[0]["secret"].as_str().unwrap().to_owned());
        let secret = directory.write("browser-client-secret", secret.as_bytes());
        // Synthetic lab-only raw 32-byte key; never production key material.
        let session_key = directory.write("session-key", &[0xA5; 32]);
        let control_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let browser_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let control = control_reservation.local_addr().unwrap();
        let browser = browser_reservation.local_addr().unwrap();
        assert_ne!(control, browser);
        let ca = if case == Case::WrongCa {
            // Valid X.509, but this leaf cannot anchor the control server's chain.
            // Avoid depending on an unprovided second PKI fixture.
            "control-operator-client.pem"
        } else {
            "ca.pem"
        };
        let server_name = if case == Case::WrongName {
            "wrong-control.invalid"
        } else {
            "control-plane-api"
        };
        let config = serde_json::json!({
            "version": 1, "public_origin": "https://console.example", "client_id": "apex-browser",
            "client_secret_file": secret,
            "session_keys": [{"usage": "active", "id": "root-fixture", "file": session_key}],
            "management": {
                "server_name": server_name,
                "ca_file": directory.path.join(ca),
                "certificate_file": directory.path.join("control-operator-client.pem"),
                "key_file": directory.path.join("control-operator-client.key")
            },
            "session_max_age_secs": 3600, "idle_timeout_secs": 900,
            "max_in_flight": 16, "request_timeout_secs": 30,
            "global_scope_catalog": ["acme/prod"]
        });
        let config = directory.write("browser.json", &serde_json::to_vec(&config).unwrap());
        let id = uuid::Uuid::now_v7().simple().to_string();
        let root_app = format!("apex_rb_root_{id}");
        Self {
            root_url: pg::named_url(schema_url, &root_app),
            observer_url: pg::named_url(schema_url, &format!("apex_rb_observer_{id}")),
            proxy_id: uuid::Uuid::now_v7().to_string(),
            root_app,
            directory,
            config,
            pki_root,
            issuer,
            control,
            browser,
            control_reservation: Some(control_reservation),
            browser_reservation: Some(browser_reservation),
        }
    }

    pub fn configure(&mut self, command: &mut Command, case: Case, selector: &str) {
        let ui_artifacts = std::env::var_os("APEX_UI_ARTIFACT_DIR");
        // All mutation is per-child; parallel parent tests never alter process env.
        for (key, _) in std::env::vars_os() {
            let upper = key.to_string_lossy().to_ascii_uppercase();
            if upper.starts_with("APEX_")
                || matches!(
                    upper.as_str(),
                    "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
                )
            {
                command.env_remove(key);
            }
        }
        command.envs([
            (support::CHILD, selector),
            (support::OBSERVER, self.observer_url.as_str()),
            (support::ROOT_APP, self.root_app.as_str()),
            (support::PROXY_ID, self.proxy_id.as_str()),
            ("APEX_CONTROL_POSTGRES_URL", self.root_url.as_str()),
            ("APEX_CONTROL_POSTGRES_POOL_SIZE", "1"),
            ("APEX_CONTROL_PROXY_PROFILE", "production"),
            ("APEX_ALLOW_POSTGRES_PLAINTEXT", "1"),
            ("APEX_BROWSER_TEST_PKI_DIR", self.pki_root.as_str()),
            ("APEX_BROWSER_KEYCLOAK_ISSUER", self.issuer.as_str()),
            ("APEX_CONTROL_KEYCLOAK_ISSUER", self.issuer.as_str()),
            ("APEX_CONTROL_KEYCLOAK_AUDIENCE", "apex-control-gateway"),
            ("APEX_CONTROL_KEYCLOAK_EXPECTED_TYP", "Bearer"),
            ("APEX_CONTROL_KEYCLOAK_JWKS_REFRESH_SECS", "30"),
            ("APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS", "120"),
            ("APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS", "3600"),
            ("RUST_LOG", "off"),
            ("RUST_BACKTRACE", "0"),
        ]);
        if case == Case::BrowserJourney
            && let Some(directory) = ui_artifacts
        {
            command.env("APEX_UI_ARTIFACT_DIR", directory);
        }
        command
            .env("APEX_CONTROL_BIND_ADDR", self.control.to_string())
            .env(support::BROWSER_ADDR, self.browser.to_string())
            .env("APEX_CONTROL_TRUSTED_SECRET_BASE", &self.directory.path)
            .env(
                "APEX_CONTROL_OUTBOX_BASE",
                self.directory.path.join("unused-outbox"),
            )
            .env(
                "APEX_CONTROL_INBOX_BASE",
                self.directory.path.join("unused-inbox"),
            );
        for (variable, file) in [
            ("APEX_CONTROL_SERVER_CERT_FILE", "control-plane-server.pem"),
            ("APEX_CONTROL_SERVER_KEY_FILE", "control-plane-server.key"),
            ("APEX_CONTROL_CLIENT_CA_FILE", "ca.pem"),
            ("APEX_CONTROL_KEYCLOAK_CA_FILE", "ca.pem"),
            ("APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE", "mcp-gateway-token"),
        ] {
            command.env(variable, self.directory.path.join(file));
        }
        if case.browser() {
            command
                .env("APEX_CONTROL_BROWSER_BIND_ADDR", self.browser.to_string())
                .env("APEX_CONTROL_BROWSER_CONFIG_FILE", &self.config);
        }
        // Retain the deliberately occupied socket until child cleanup is proved.
        if case != Case::OccupiedControl {
            drop(self.control_reservation.take());
        }
        if case != Case::OccupiedBrowser {
            drop(self.browser_reservation.take());
        }
    }
}
