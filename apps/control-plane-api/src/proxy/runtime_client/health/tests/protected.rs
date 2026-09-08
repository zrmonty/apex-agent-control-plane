use super::*;
use std::{fs, path::PathBuf};

struct ConfigFiles {
    base: PathBuf,
}
impl ConfigFiles {
    fn new(fixture: &Fixture, pki: &pki::Pki) -> Self {
        let artifact = PathBuf::from(std::env::var_os("APEX_RUNTIME_FIXTURE_PATH").unwrap());
        let parent = std::env::var_os("APEX_HEALTH_TEST_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| artifact.parent().unwrap().parent().unwrap().to_owned());
        let base = parent.join(format!("controller-health-test-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&base).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let files = Self { base };
        for (file, source) in [
            ("ca.pem", "ca.pem"),
            ("controller.pem", "control-operator-client.pem"),
            ("controller.key", "control-operator-client.key"),
        ] {
            files.write(file, &pki.read("trusted-host", source));
        }
        files.write("execution.json", &serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "installation_id": INSTALLATION, "worker_id": "health-test",
            "endpoint": fixture.endpoint(), "server_name": "control-plane-api", "ca_file": "ca.pem",
            "client_cert_file": "controller.pem", "client_key_file": "controller.key",
            "scopes": [{"workspace_id": "acme", "namespace_id": "prod"}]
        })).unwrap());
        files
    }
    fn write(&self, file: &str, contents: &[u8]) {
        let path = self.base.join(file);
        fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        // Windows test-support intentionally bypasses ACL inspection in the
        // existing shared permission helper. These tests prove file generations,
        // not production Windows ACL enforcement.
    }
    fn load(&self) -> RuntimeExecutionConfig {
        RuntimeExecutionConfig::load(&self.base, &self.base.join("execution.json")).unwrap()
    }
}
impl Drop for ConfigFiles {
    fn drop(&mut self) {
        // Only the four files created by this fixture, never recursive removal.
        for file in [
            "ca.pem",
            "controller.pem",
            "controller.key",
            "execution.json",
        ] {
            let _ = fs::remove_file(self.base.join(file));
        }
        let _ = fs::remove_dir(&self.base);
    }
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_rechecks_original_protected_files_before_and_after_rpc() {
    let pki = pki::Pki::require();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for before in [false, true] {
        for file in [
            "execution.json",
            "ca.pem",
            "controller.pem",
            "controller.key",
        ] {
            let fixture = Fixture::new(&pki, if before { Mode::Good } else { Mode::PostConfig });
            let files = ConfigFiles::new(&fixture, &pki);
            let config = files.load();
            *fixture.revoke.lock().unwrap() = Some(files.base.join(file));
            runtime.block_on(async {
                let mut client = RuntimeExecutionClient::connect(&config, deadline())
                    .await
                    .unwrap();
                if before {
                    files.write(file, b"changed-config-before-health");
                }
                let (request, observed) = inputs();
                let result = client
                    .observe_health(&request, &observed, deadline(), &|| Ok(()))
                    .await;
                assert!(result.is_err(), "changed {file}, before={before}");
            });
            assert_eq!(fixture.requests.lock().unwrap().len(), usize::from(!before));
        }
    }
}
