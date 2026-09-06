use super::fixture::{Fixture, TOKEN};
use std::{
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

pub struct Process(Child);
impl Process {
    pub fn control(f: &Fixture) -> Self {
        Self::control_mode(f, false)
    }
    pub fn control_registration(f: &Fixture) -> Self {
        Self::control_mode(f, true)
    }
    fn control_mode(f: &Fixture, managed: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_apex-control-plane-api"));
        clean(&mut command);
        if managed {
            command
                .env("APEX_CONTROL_MANAGED_AUTHORITY_FILE", "managed.json")
                .env(
                    "APEX_CONTROL_MCP_ALLOWED_SCOPES",
                    "workspace/namespace,workspace/namespace-two",
                );
        }
        command
            .envs([
                ("APEX_CONTROL_POSTGRES_URL", f.database.url.as_str()),
                ("APEX_CONTROL_POSTGRES_POOL_SIZE", "1"),
                ("APEX_ALLOW_POSTGRES_PLAINTEXT", "1"),
                ("APEX_CONTROL_PROXY_PROFILE", "production"),
                ("APEX_CONTROL_RUNTIME_PEER_POLICY_FILE", "peer.json"),
                ("APEX_CONTROL_RUNTIME_ENROLLMENT_FILE", "enrollment.json"),
                (
                    "APEX_CONTROL_RUNTIME_DEPLOYMENT_BINDINGS_FILE",
                    "deployment.json",
                ),
                (
                    "APEX_CONTROL_RUNTIME_EXECUTION_CONFIG_FILE",
                    "execution.json",
                ),
            ])
            .env(
                "APEX_CONTROL_OPERATOR_TOKENS",
                format!("{TOKEN}|workspace/namespace,workspace/namespace-two"),
            )
            .env("APEX_CONTROL_BIND_ADDR", f.cp.to_string())
            .env("APEX_CONTROL_TRUSTED_SECRET_BASE", f.root.join("control"));
        for (key, file) in [
            ("SERVER_CERT_FILE", "server.pem"),
            ("SERVER_KEY_FILE", "server.key"),
            ("CLIENT_CA_FILE", "ca.pem"),
            ("MCP_GATEWAY_TOKEN_FILE", "gateway-token"),
        ] {
            command.env(
                format!("APEX_CONTROL_{key}"),
                f.root.join("control").join(file),
            );
        }
        Self::start(command, f.cp)
    }
    pub fn agent(f: &Fixture) -> Self {
        let mut command = Command::new("/binding-tests/task3a-agent");
        clean(&mut command);
        command.arg("--config-dir").arg(f.root.join("config"));
        Self::start(command, f.agent)
    }
    fn start(mut command: Command, address: SocketAddr) -> Self {
        let mut child = Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let end = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "production root exited before listener"
            );
            if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                return child;
            }
            assert!(Instant::now() < end, "production root startup deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn stop(&mut self) {
        if self.0.try_wait().unwrap().is_some() {
            return;
        }
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let end = Instant::now() + Duration::from_secs(155);
        while self.0.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "owned physical shutdown deadline");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn clean(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("APEX_")
            || matches!(
                name.as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        {
            command.env_remove(key);
        }
    }
    command.env("RUST_LOG", "off").env("RUST_BACKTRACE", "0");
}
pub async fn channel(f: &Fixture, address: SocketAddr, identity: &str) -> Channel {
    Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("control-plane-api")
                .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
                .identity(f.pki.identity("trusted-host", identity)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap()
}
pub fn operator<T>(value: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(value);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    request.set_timeout(Duration::from_secs(10));
    request
}

// Browser-equivalent retry of an explicit dependency refusal, never malformed
// input or a timeout. Callers clone the SAME request/UUID into every invocation.
pub async fn management<T, F, U>(mut call: F) -> Result<T, tonic::Status>
where
    F: FnMut() -> U,
    U: std::future::Future<Output = Result<T, tonic::Status>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    for attempt in 0..4 {
        let result = tokio::time::timeout_at(deadline, call())
            .await
            .map_err(|_| tonic::Status::deadline_exceeded("fixture management deadline"))?;
        if result
            .as_ref()
            .err()
            .is_some_and(|e| e.code() == tonic::Code::Unavailable)
            && attempt < 3
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        return result;
    }
    unreachable!()
}
