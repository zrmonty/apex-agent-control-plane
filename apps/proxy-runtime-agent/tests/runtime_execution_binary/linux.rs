use crate::{
    pki::{AGENT, CONTROLLER, Pki},
    server::{Callback, CallbackState, Listener},
    support::*,
};
use apex_proxy_runtime_agent::proto::{
    self, runtime_execution_service_client::RuntimeExecutionServiceClient,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
struct Process {
    child: std::process::Child,
    root: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn write(root: &std::path::Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn binary_loads_protected_files_serves_mtls_and_poison_refresh_requires_restart() {
    let pki = Pki::require();
    let state = CallbackState::new();
    let callback = Listener::start(
        &pki,
        Callback {
            state: Arc::clone(&state),
            policy: policy(&pki, "client-policy", false),
        },
        false,
    );
    let root = PathBuf::from("/root").join(format!("apex-task2-process-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let config = json!({"schema_version":1,"listen":addr.to_string(),"installation_id":INSTALL,"agent_identity_id":"client-agent","enrollment_version":"enrollment-1","host_policy_version":"host-1","authority_endpoint":callback.endpoint,"authority_tls_server_name":"control-plane-api"});
    write(&root, "agent.json", &serde_json::to_vec(&config).unwrap());
    let grant = json!({"installationId":INSTALL,"workspaceId":"work","namespaceId":"ns"});
    let policy = json!({"schemaVersion":1,"version":"client-policy","validFromUnixUs":"1","expiresAtUnixUs":i64::MAX.to_string(),"peers":[{"certificateSha256":crate::pki::hex(&pki.pin(CONTROLLER)),"identityId":"client-controller","role":"controller","revoked":false,"grants":[grant]}]});
    write(
        &root,
        "peer-policy.json",
        &serde_json::to_vec(&policy).unwrap(),
    );
    let t = target();
    let catalog = json!({"schema_version":1,"version":"c1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":[{"installation_id":INSTALL,"workspace_id":"work","namespace_id":"ns","proxy_id":t.proxy_id,"revision_id":t.revision_id,"host_policy_version":"host-1","deployment_bindings_version":"bindings-1","config_hash":HASH,"authority_profile_ref":"live","authority_profile_version":"v1","image_catalog_id":"gateway","materials":(1..=13).map(|n|json!({"role":proto::RuntimeMaterialRole::try_from(n).unwrap().as_str_name(),"reference":format!("secret://deployment/m{n}"),"version":"v1","source_name":format!("m{n}")})).collect::<Vec<_>>()}]});
    write(
        &root,
        "launch-catalog.json",
        &serde_json::to_vec(&catalog).unwrap(),
    );
    for (name, source) in [
        ("server-ca.pem", "ca.pem"),
        ("server-cert.pem", "control-plane-server.pem"),
        ("server-key.pem", "control-plane-server.key"),
        ("authority-ca.pem", "ca.pem"),
        ("authority-client-cert.pem", "agent-workload-client.pem"),
        ("authority-client-key.pem", "agent-workload-client.key"),
    ] {
        write(&root, name, &pki.read("trusted-host", source));
    }
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_apex-proxy-runtime-agent"))
        .arg("--config-dir")
        .arg(&root)
        .spawn()
        .unwrap();
    let mut process = Process { child, root };
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .identity(pki.identity("trusted-host", CONTROLLER));
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_timeout(Duration::from_millis(200));
    let deadline = Instant::now() + Duration::from_secs(5);
    let channel = loop {
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "production agent exited before binding"
        );
        if let Ok(channel) = endpoint.connect().await {
            break channel;
        }
        assert!(
            Instant::now() < deadline,
            "production listener startup deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut client = RuntimeExecutionServiceClient::new(channel.clone());
    let req = || proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(target()),
        operation_id: query().get_ref().operation_id.clone(),
        command_id: query().get_ref().command_id.clone(),
        config_hash: HASH.into(),
    };
    assert_eq!(
        client.reconcile_runtime(req()).await.unwrap_err().message(),
        "RUNTIME_NOT_SERVING_EFFECT_OWNER_UNAVAILABLE"
    );
    assert_eq!(
        *state
            .request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .observed_controller_certificate_sha256,
        pki.pin(CONTROLLER)
    );
    assert_eq!(state.resolve_calls.load(Ordering::SeqCst), 1);
    let mut legacy = proto::proxy_runtime_agent_client::ProxyRuntimeAgentClient::new(channel);
    assert_eq!(
        legacy.remove_runtime(target()).await.unwrap_err().code(),
        tonic::Code::Unimplemented
    );
    // An observed malformed replacement must not retain the original valid policy.
    write(&process.root, "peer-policy.json", b"invalid");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        client.reconcile_runtime(req()).await.unwrap_err().message(),
        "RUNTIME_POLICY_UNAVAILABLE"
    );
    assert_eq!(state.resolve_calls.load(Ordering::SeqCst), 1);
    write(
        &process.root,
        "peer-policy.json",
        &serde_json::to_vec(&policy).unwrap(),
    );
    // Changing any static transport/config file latches restart-required, even if restored.
    let mut changed = config.clone();
    changed["schema_version"] = 0.into();
    write(
        &process.root,
        "agent.json",
        &serde_json::to_vec(&changed).unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    write(
        &process.root,
        "agent.json",
        &serde_json::to_vec(&config).unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        client.reconcile_runtime(req()).await.unwrap_err().message(),
        "RUNTIME_POLICY_UNAVAILABLE"
    );
    assert_eq!(state.resolve_calls.load(Ordering::SeqCst), 1);
    drop(client);
    drop(legacy);
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(process.child.id()).unwrap()).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "signal must join reader and listener"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    callback.shutdown().await;
    let _ = AGENT;
}
