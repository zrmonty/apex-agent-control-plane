use super::{
    Case,
    material::{INSTALLATION, Materials},
    operation::Fixture,
    pki::{self, Pki},
    support::OwnedDir,
};
use apex_control_plane_api::proto::{CheckRuntimeAuthorityRequest, RuntimeAuthorityAction};
use std::{net::TcpListener, process::Command};
use zeroize::Zeroizing;

pub(super) const CHILD: &str = "APEX_RUNTIME_ROOT_CHILD";
pub(super) const APPLICATION: &str = "APEX_RUNTIME_ROOT_APPLICATION";
pub(super) const QUERY: &str = "APEX_RUNTIME_ROOT_QUERY";
pub(super) const CLEAN: &str = "ROOT_AUTHORITY_CLEAN_WHILE_ALIVE";

pub(super) struct RootFixture {
    pub directory: OwnedDir,
    pub name: String,
    pub url: String,
    socket: Option<TcpListener>,
    address: std::net::SocketAddr,
}

impl RootFixture {
    pub fn new(operation: &Fixture) -> Self {
        let pki = Pki::require();
        let metadata = Materials::new(operation, &pki);
        let directory = OwnedDir::new();
        for name in [
            "ca.pem",
            "control-plane-server.pem",
            "control-plane-server.key",
            "mcp-gateway-token",
        ] {
            directory.write(name, &Zeroizing::new(pki.read("trusted-host", name)));
        }
        directory.write("peer.json", &serde_json::to_vec(&metadata.peer).unwrap());
        directory.write(
            "enrollment.json",
            &serde_json::to_vec(&metadata.enrollment).unwrap(),
        );
        let request = CheckRuntimeAuthorityRequest {
            schema_version: 1,
            target: Some(operation.target.clone()),
            operation_id: operation.operation.operation_id.clone(),
            command_id: uuid::Uuid::now_v7().to_string(),
            action: RuntimeAuthorityAction::CheckCurrentOperation as i32,
            installation_id: INSTALLATION.into(),
            observed_controller_certificate_sha256: pki.pin(pki::CONTROLLER).to_vec(),
        };
        directory.write("query.json", &serde_json::to_vec(&request).unwrap());
        let name = format!("authority_root_{}", uuid::Uuid::now_v7().simple());
        let url = format!("{}&application_name={name}", operation.database.url);
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        Self {
            directory,
            name,
            url,
            socket: Some(socket),
            address,
        }
    }

    pub fn configure(&mut self, command: &mut Command, case: Case, selector: &str) {
        let pki = std::path::PathBuf::from(std::env::var_os("APEX_BROWSER_TEST_PKI_DIR").unwrap())
            .canonicalize()
            .expect("required absolute PKI root for the child");
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
        command
            .envs([
                (CHILD, selector),
                (APPLICATION, &self.name),
                ("APEX_CONTROL_POSTGRES_URL", &self.url),
                ("APEX_CONTROL_POSTGRES_POOL_SIZE", "1"),
                ("APEX_ALLOW_POSTGRES_PLAINTEXT", "1"),
                ("APEX_CONTROL_PROXY_PROFILE", "production"),
                // Explicit existing lab operator resolver; callback never uses it.
                (
                    "APEX_CONTROL_OPERATOR_TOKENS",
                    "runtime-root-lab-only|workspace/namespace",
                ),
                ("RUST_BACKTRACE", "0"),
                ("RUST_LOG", "off"),
            ])
            .env("APEX_BROWSER_TEST_PKI_DIR", pki)
            .env("APEX_CONTROL_BIND_ADDR", self.address.to_string())
            .env("APEX_CONTROL_TRUSTED_SECRET_BASE", &self.directory.path)
            .env(QUERY, self.directory.path.join("query.json"));
        for (variable, file) in [
            ("APEX_CONTROL_SERVER_CERT_FILE", "control-plane-server.pem"),
            ("APEX_CONTROL_SERVER_KEY_FILE", "control-plane-server.key"),
            ("APEX_CONTROL_CLIENT_CA_FILE", "ca.pem"),
            ("APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE", "mcp-gateway-token"),
        ] {
            command.env(variable, self.directory.path.join(file));
        }
        if case != Case::Disabled {
            command.env("APEX_CONTROL_RUNTIME_PEER_POLICY_FILE", "peer.json");
            if case != Case::Partial {
                command.env(
                    "APEX_CONTROL_RUNTIME_ENROLLMENT_FILE",
                    if case == Case::Missing {
                        "missing.json"
                    } else {
                        "enrollment.json"
                    },
                );
            }
        }
        if case != Case::Occupied {
            drop(self.socket.take());
        }
    }
}
