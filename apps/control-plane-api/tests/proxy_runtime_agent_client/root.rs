use super::{
    material::Materials,
    operation::Fixture,
    pki::Pki,
    process::{self, Directory, Process},
};
use apex_control_plane_api::proto::CheckRuntimeAuthorityRequest;
use std::{
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct Root {
    // Processes end before staged files or the caller's schema is removed.
    process: Process,
    directory: Directory,
    endpoint: String,
}
impl Root {
    pub fn direct(
        &self,
        pki: &Pki,
        request: CheckRuntimeAuthorityRequest,
    ) -> apex_control_plane_api::proto::RuntimeAuthoritySnapshot {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut client = super::transport::client(pki, &self.endpoint, super::pki::AGENT).await;
            super::transport::within(client.check_runtime_authority(request))
                .await
                .expect("actual production callback/PG positive control")
                .into_inner()
        })
    }

    pub fn start(fixture: &Fixture, pki: &Pki, materials: &Materials) -> Self {
        let directory = Directory::new();
        for name in [
            "ca.pem",
            "control-plane-server.pem",
            "control-plane-server.key",
            "mcp-gateway-token",
        ] {
            directory.write(name, &pki.read("trusted-host", name));
        }
        directory.write("peer.json", &serde_json::to_vec(&materials.peer).unwrap());
        directory.write(
            "enrollment.json",
            &serde_json::to_vec(&materials.enrollment).unwrap(),
        );
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_apex-control-plane-api"));
        process::clean(&mut command);
        command
            .envs([
                ("APEX_CONTROL_POSTGRES_URL", fixture.database.url.as_str()),
                ("APEX_CONTROL_POSTGRES_POOL_SIZE", "1"),
                ("APEX_ALLOW_POSTGRES_PLAINTEXT", "1"),
                ("APEX_CONTROL_PROXY_PROFILE", "production"),
                (
                    "APEX_CONTROL_OPERATOR_TOKENS",
                    "client-root-lab-only|workspace/namespace",
                ),
                ("APEX_CONTROL_RUNTIME_PEER_POLICY_FILE", "peer.json"),
                ("APEX_CONTROL_RUNTIME_ENROLLMENT_FILE", "enrollment.json"),
            ])
            .env("APEX_CONTROL_BIND_ADDR", address.to_string())
            .env("APEX_CONTROL_TRUSTED_SECRET_BASE", &directory.path)
            .stdout(Stdio::null());
        for (key, file) in [
            ("APEX_CONTROL_SERVER_CERT_FILE", "control-plane-server.pem"),
            ("APEX_CONTROL_SERVER_KEY_FILE", "control-plane-server.key"),
            ("APEX_CONTROL_CLIENT_CA_FILE", "ca.pem"),
            ("APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE", "mcp-gateway-token"),
        ] {
            command.env(key, directory.path.join(file));
        }
        drop(reservation);
        let mut process = Process::spawn(&mut command);
        let started = Instant::now();
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "production root exited before TLS listener"
            );
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(8),
                "production root startup watchdog"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Self {
            process,
            directory,
            endpoint: format!("https://{address}"),
        }
    }

    pub fn probe(
        &self,
        materials: &Materials,
        request: &CheckRuntimeAuthorityRequest,
        config_hash: &str,
        caller: &str,
    ) -> serde_json::Value {
        let executable = PathBuf::from(
            std::env::var_os("APEX_RUNTIME_AUTHORITY_CLIENT_PROBE").expect(
                "build the actual runtime_authority_probe example and set its exact path; no skip",
            ),
        )
        .canonicalize()
        .expect("existing separately compiled runtime-agent probe required");
        assert!(executable.is_file());
        let input = serde_json::json!({
            "authority_endpoint": self.endpoint, "peer_policy": materials.peer,
            "request": request, "config_hash": config_hash, "caller": caller,
        });
        let path = self.directory.write(
            &format!("input-{}.json", uuid::Uuid::now_v7()),
            &serde_json::to_vec(&input).unwrap(),
        );
        let mut command = Command::new(executable);
        process::clean(&mut command);
        command
            .arg(path)
            .env("APEX_RUNTIME_AUTHORITY_PROBE", "1")
            .env(
                "APEX_BROWSER_TEST_PKI_DIR",
                std::env::var_os("APEX_BROWSER_TEST_PKI_DIR").unwrap(),
            );
        process::probe(&mut command, &self.directory)
    }
    pub fn finish(self) {
        self.process.finish();
    }
}

pub(super) fn assert_refusal(value: serde_json::Value, expected: &str) {
    assert!(value.get("snapshot").is_none());
    let code = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("static application refusal");
    assert_eq!(
        code, expected,
        "transport/watchdog/dependency failure is not a specific refusal"
    );
}
