use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let root =
            Self(PathBuf::from("/root").join(format!("apex-task4m-{}", uuid::Uuid::now_v7())));
        fs::create_dir(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let (p, c) = crate::owner::tests::documents();
        let (i, a, t) = crate::owner::tests::network::execution_documents();
        for (name, bytes) in [
            ("peer-policy.json", p),
            ("launch-catalog.json", c),
            ("image-catalog.json", i),
            ("authority-profiles.json", a),
            ("tool-bindings.json", t),
        ] {
            root.write(name, &bytes);
        }
        for name in [
            "server-ca.pem",
            "server-cert.pem",
            "server-key.pem",
            "authority-ca.pem",
            "authority-client-cert.pem",
            "authority-client-key.pem",
        ] {
            root.write(name, b"synthetic-unused-transport");
        }
        root.agent(false);
        root
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.0.join(name), bytes).unwrap();
        fs::set_permissions(self.0.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn agent(&self, enabled: bool) {
        let mut value = serde_json::json!({"schema_version":1,"listen":"127.0.0.1:9443",
            "installation_id":"018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01","agent_identity_id":"agent",
            "enrollment_version":"v1","host_policy_version":"host-v1","authority_endpoint":"https://authority.example",
            "authority_tls_server_name":"authority.example","execution":{"journal_root":"/j","staging_root":"/s",
            "material_root":"/m","docker_executable":"/bin/docker","docker_socket":"/run/docker.sock","docker_config_root":"/d",
            "cosign_executable":"/bin/cosign","cosign_cache_root":"/c"}});
        if enabled {
            value["execution"]["network_profile"] = "isolated-bridge-v1".into();
        }
        self.write("agent.json", &serde_json::to_vec(&value).unwrap());
    }
    fn directory(&self) -> Directory {
        Directory::open(&self.0).unwrap()
    }
    fn fingerprint(&self) -> [u8; 32] {
        Deployment::transport(&self.directory(), None)
            .unwrap()
            .fingerprint
    }
    fn load(&self) -> Result<(Deployment, Metadata), &'static str> {
        // Actual production refresh path, not startup/engine or TLS acceptance.
        Deployment::load(&self.directory(), Some(self.fingerprint()))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn protected_network_file_opt_in_loads_and_legacy_does_not_read_it() {
    let root = Root::new();
    assert!(root.load().unwrap().1.network.is_none());
    root.write("network-catalog.json", b"invalid");
    assert!(root.load().unwrap().1.network.is_none());
    root.agent(true);
    assert!(root.load().is_err());
    root.write(
        "network-catalog.json",
        &serde_json::to_vec(&crate::network_catalog::tests::fixture()).unwrap(),
    );
    assert!(
        root.load().unwrap().1.network.is_some(),
        "fixed protected network file must load"
    );
    fs::remove_file(root.0.join("network-catalog.json")).unwrap();
    assert!(root.load().is_err());
}
#[test]
fn protected_network_file_refuses_links_permissions_size_and_mode_change() {
    let root = Root::new();
    let old = root.fingerprint();
    root.agent(true);
    assert!(matches!(
        Deployment::load(&root.directory(), Some(old)),
        Err("RUNTIME_RESTART_REQUIRED")
    ));
    let bytes = serde_json::to_vec(&crate::network_catalog::tests::fixture()).unwrap();
    root.write("network-catalog.json", &bytes);
    assert!(root.load().is_ok());
    fs::set_permissions(
        root.0.join("network-catalog.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(root.load().is_err());
    root.write("network-catalog.json", &bytes);
    fs::hard_link(root.0.join("network-catalog.json"), root.0.join("copy")).unwrap();
    assert!(root.load().is_err());
    fs::remove_file(root.0.join("copy")).unwrap();
    fs::remove_file(root.0.join("network-catalog.json")).unwrap();
    symlink("peer-policy.json", root.0.join("network-catalog.json")).unwrap();
    assert!(root.load().is_err());
    fs::remove_file(root.0.join("network-catalog.json")).unwrap();
    root.write("network-catalog.json", &vec![b'x'; 262145]);
    assert!(root.load().is_err());
    assert!(
        root.directory()
            .read("network-catalog.json", 65536)
            .is_err()
    );
}

#[test]
fn actual_protected_refresh_invalidates_network_metadata_without_stale_fallback() {
    use crate::owner::{Reader, snapshot};
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    let root = Root::new();
    root.agent(true);
    root.write(
        "network-catalog.json",
        &serde_json::to_vec(&crate::network_catalog::tests::fixture()).unwrap(),
    );
    let fingerprint = root.fingerprint();
    let directory = root.directory();
    let (entered, seen) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let mut calls = 0;
    let reader = Reader::start(move || {
        calls += 1;
        if calls == 2 {
            entered.send(()).unwrap();
            held.recv().unwrap();
        }
        Deployment::load(&directory, Some(fingerprint)).map(|(_, m)| m)
    })
    .unwrap();
    // Release a held reader on assertion failure before its owning join runs.
    struct Release(Option<mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(s) = self.0.take() {
                let _ = s.send(());
            }
        }
    }
    let release = Release(Some(release));
    seen.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(snapshot(&reader.shared).unwrap().network.is_some());
    root.write("network-catalog.json", b"invalid-replacement");
    drop(release);
    let deadline = Instant::now() + Duration::from_secs(2);
    while reader.shared.lock().unwrap().metadata.is_some() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(reader.shared.lock().unwrap().metadata.is_none());
    assert!(snapshot(&reader.shared).is_err());
    drop(reader); // Actual reader joined before its protected fixture root removal.
}
