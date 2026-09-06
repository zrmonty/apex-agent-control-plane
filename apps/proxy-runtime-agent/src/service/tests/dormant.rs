//! Real compiled production owner -> real mTLS callback fixture -> Cosign/Docker.
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
const IMAGE: &str = "ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8";
struct Binary(Child);
impl Drop for Binary {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
            let _ = self.0.wait();
        }
    }
}
impl Binary {
    fn stop(mut self) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.0.id() as i32).unwrap(),
            rustix::process::Signal::TERM,
        )
        .unwrap();
        assert!(self.0.wait().unwrap().success());
    }
}
fn write(root: &Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}
fn profiles(root: &Path, name: &str, mut doc: serde_json::Value) {
    if let Ok(bytes) = fs::read(root.join(name)) {
        let old: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id = doc["profiles"][0]["proxy_id"].clone();
        for p in old["profiles"].as_array().unwrap() {
            if p["proxy_id"] != id {
                doc["profiles"].as_array_mut().unwrap().push(p.clone());
            }
        }
    }
    write(root, name, &serde_json::to_vec(&doc).unwrap());
}
fn catalogs(root: &Path, f: &Fixture) {
    let (policy, launch) = documents(&f.pki);
    let mut launch: serde_json::Value = serde_json::from_slice(&launch).unwrap();
    let reply = f.callback.reply.lock().unwrap();
    let config = reply.configuration.as_ref().unwrap();
    let t = reply.authority.as_ref().unwrap().target.as_ref().unwrap();
    launch["profiles"][0]["proxy_id"] = t.proxy_id.clone().into();
    launch["profiles"][0]["revision_id"] = t.revision_id.clone().into();
    write(root, "peer-policy.json", &policy);
    profiles(root, "launch-catalog.json", launch);
    write(root,"image-catalog.json",&serde_json::to_vec(&serde_json::json!({"schema_version":1,"images":[{"id":"gateway","image_ref":IMAGE,
        "signing":{"certificate_oidc_issuer":"https://accounts.google.com","certificate_identity":"keyless@projectsigstore.iam.gserviceaccount.com"}}]})).unwrap());
    let authority = serde_json::json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":[{
        "installation_id":INSTALL,"workspace_id":"work","namespace_id":"ns","proxy_id":t.proxy_id,"host_policy_version":"host-1","reference":"live","version":"v1",
        "governance":{"endpoint":"https://governance.example","tls_server_name":"governance.example"},
        "evidence":{"endpoint":"https://evidence.example","tls_server_name":"evidence.example"}}]});
    profiles(root, "authority-profiles.json", authority);
    let tools = serde_json::json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":[{
        "installation_id":INSTALL,"workspace_id":"work","namespace_id":"ns","proxy_id":t.proxy_id,"revision_id":t.revision_id,
        "host_policy_version":"host-1","deployment_bindings_version":"bindings-1","config_hash":config.config_hash,
        "entries":config.secret_refs.iter().enumerate().map(|(n,r)|serde_json::json!({"reference":r,"version":"v1","source_name":format!("tool{n}")})).collect::<Vec<_>>() }]});
    profiles(root, "tool-bindings.json", tools);
}
fn configure(root: &Path, f: &Fixture) -> std::net::SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let config = root.join("config");
    let execution = serde_json::json!({"journal_root":root.join("journal"),"staging_root":root.join("staging"),"material_root":root.join("material"),
        "docker_executable":"/apex-engine-tools/docker","docker_socket":"/run/apex-docker.sock","docker_config_root":root.join("docker"),
        "cosign_executable":"/apex-signature-tools/cosign","cosign_cache_root":root.join("cosign")});
    write(&config,"agent.json",&serde_json::to_vec(&serde_json::json!({"schema_version":1,"listen":addr.to_string(),"installation_id":INSTALL,
        "agent_identity_id":"client-agent","enrollment_version":"enrollment-1","host_policy_version":"host-1","authority_endpoint":f.authority_endpoint,
        "authority_tls_server_name":"control-plane-api","execution":execution})).unwrap());
    addr
}
async fn start(
    root: &Path,
    f: &Fixture,
) -> (
    Binary,
    RuntimeExecutionServiceClient<tonic::transport::Channel>,
) {
    start_binary(root, f, "/binding-tests/task3a-agent").await
}
async fn start_binary(
    root: &Path,
    f: &Fixture,
    binary: &str,
) -> (
    Binary,
    RuntimeExecutionServiceClient<tonic::transport::Channel>,
) {
    let addr = configure(root, f);
    let config = root.join("config");
    let mut child = Binary(
        Command::new(binary)
            .arg("--config-dir")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
        .identity(f.pki.identity("trusted-host", CONTROLLER));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "production agent exited before binding"
        );
        if let Ok(c) = Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(tls.clone())
            .unwrap()
            .connect()
            .await
        {
            return (
                child,
                RuntimeExecutionServiceClient::new(c)
                    .max_encoding_message_size(4096)
                    .max_decoding_message_size(16_384),
            );
        }
        assert!(Instant::now() < deadline, "production listener unavailable");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn setup(root: &Path, f: &Fixture) {
    fs::create_dir(root).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for n in [
        "config", "journal", "staging", "material", "docker", "cosign",
    ] {
        fs::create_dir(root.join(n)).unwrap();
        fs::set_permissions(root.join(n), fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (name, source) in [
        ("server-ca.pem", "ca.pem"),
        ("server-cert.pem", "control-plane-server.pem"),
        ("server-key.pem", "control-plane-server.key"),
        ("authority-ca.pem", "ca.pem"),
        ("authority-client-cert.pem", "agent-workload-client.pem"),
        ("authority-client-key.pem", "agent-workload-client.key"),
    ] {
        write(
            &root.join("config"),
            name,
            &f.pki.read("trusted-host", source),
        );
    }
    for n in 1..=13 {
        write(
            &root.join("material"),
            &format!("m{n}"),
            if n == 1 {
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            } else {
                b"task3a-material-secret-canary"
            },
        );
    }
    for (n, _) in f
        .callback
        .reply
        .lock()
        .unwrap()
        .configuration
        .as_ref()
        .unwrap()
        .secret_refs
        .iter()
        .enumerate()
    {
        write(
            &root.join("material"),
            &format!("tool{n}"),
            b"task3a-tool-secret-canary",
        );
    }
    catalogs(&root.join("config"), f);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_provisioning_recovers_original_instance() {
    let f = Fixture::start().await;
    {
        let mut reply = f.callback.reply.lock().unwrap();
        let c = reply.configuration.as_mut().unwrap();
        c.image_ref = IMAGE.into();
        c.runtime_manifest_hash = crate::runtime_manifest_hash(c).unwrap();
    }
    let base = PathBuf::from(
        std::env::var_os("APEX_TASK3A_ROOT").expect("dedicated daemon volume mountpoint required"),
    );
    let root = base.join(format!("case-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let (agent, mut client) = start(&root, &f).await;
    let first = client
        .reconcile_runtime(request())
        .await
        .expect("actual dormant provisioning")
        .into_inner();
    assert_eq!(
        first.observed_state,
        i32::from(proto::ProxyObservedState::NotServing)
    );
    assert_eq!(first.error_code, "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE");
    let runtime = first.runtime.unwrap();
    assert!(!runtime.ready && !runtime.admitting);
    assert_eq!(runtime.target, request().target);
    let again = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.runtime.unwrap().runtime_id, runtime.runtime_id);
    drop(client);
    agent.stop();
    crate::execution::fixture_lost_create(
        &root.join("journal"),
        INSTALL,
        request().target.as_ref().unwrap(),
    );
    let mut next = request();
    next.command_id = uuid::Uuid::now_v7().to_string();
    next.target.as_mut().unwrap().fencing_token += 1;
    {
        let mut r = f.callback.reply.lock().unwrap();
        let a = r.authority.as_mut().unwrap();
        a.command_id = next.command_id.clone();
        a.target = next.target.clone();
    }
    let (agent, mut client) = start(&root, &f).await;
    let recovered = client
        .reconcile_runtime(next.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(recovered.claims, Some(next));
    let recovered = recovered.runtime.unwrap();
    assert_eq!(recovered.runtime_id, runtime.runtime_id);
    assert_eq!(recovered.target, runtime.target);
    assert_eq!(*f.callback.pin.lock().unwrap(), f.pki.pin(CONTROLLER));
    let mut retire = request();
    retire.operation_id = uuid::Uuid::now_v7().to_string();
    retire.command_id = uuid::Uuid::now_v7().to_string();
    retire.target.as_mut().unwrap().generation += 1;
    retire.target.as_mut().unwrap().fencing_token += 2;
    {
        let mut r = f.callback.reply.lock().unwrap();
        let a = r.authority.as_mut().unwrap();
        a.operation_id = retire.operation_id.clone();
        a.command_id = retire.command_id.clone();
        a.target = retire.target.clone();
        a.desired_state = 3;
    }
    let retired = client.reconcile_runtime(retire).await.unwrap().into_inner();
    assert_eq!(
        retired.observed_state,
        i32::from(proto::ProxyObservedState::Retired),
        "terminal retirement requires exact stage cleanup"
    );
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    drop(client);
    agent.stop();
    eprintln!(
        "TASK3A dormant evidence root={} container={}",
        root.display(),
        runtime.runtime_id
    );
    f.stop().await;
}

mod boundaries;
mod handoff;
mod network;
mod refusal;
fn current(f: &Fixture, r: &proto::RuntimeReconcileRequest, desired: proto::ProxyDesiredState) {
    let mut reply = f.callback.reply.lock().unwrap();
    let a = reply.authority.as_mut().unwrap();
    a.target = r.target.clone();
    a.command_id = r.command_id.clone();
    a.operation_id = r.operation_id.clone();
    a.config_hash = r.config_hash.clone();
    a.desired_state = desired.into();
    if desired == proto::ProxyDesiredState::Serving {
        let t = r.target.as_ref().unwrap();
        let c = reply.configuration.as_mut().unwrap();
        c.proxy_id = t.proxy_id.clone();
        c.revision_id = t.revision_id.clone();
        c.generation = t.generation;
        c.image_ref = IMAGE.into();
        c.config_hash = r.config_hash.clone();
        c.runtime_manifest_hash = crate::runtime_manifest_hash(c).unwrap();
    }
}
fn new_operation(mut r: proto::RuntimeReconcileRequest) -> proto::RuntimeReconcileRequest {
    r.command_id = uuid::Uuid::now_v7().to_string();
    r.operation_id = uuid::Uuid::now_v7().to_string();
    let t = r.target.as_mut().unwrap();
    t.generation += 1;
    t.fencing_token += 1;
    r
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_two_proxies_pause_and_retire_preserve_other_instance() {
    let f = Fixture::start().await;
    let first = request();
    current(&f, &first, proto::ProxyDesiredState::Serving);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("two-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let (agent, mut client) = start(&root, &f).await;
    let one = client
        .reconcile_runtime(first.clone())
        .await
        .unwrap()
        .into_inner()
        .runtime
        .unwrap();
    drop(client);
    agent.stop();
    let mut second = request();
    second.target.as_mut().unwrap().proxy_id = uuid::Uuid::now_v7().to_string();
    second.operation_id = uuid::Uuid::now_v7().to_string();
    second.command_id = uuid::Uuid::now_v7().to_string();
    current(&f, &second, proto::ProxyDesiredState::Serving);
    catalogs(&root.join("config"), &f);
    let (agent, mut client) = start(&root, &f).await;
    let two = client
        .reconcile_runtime(second.clone())
        .await
        .unwrap()
        .into_inner()
        .runtime
        .unwrap();
    assert_ne!(one.runtime_id, two.runtime_id);
    let mut pause = new_operation(first.clone());
    pause.target.as_mut().unwrap().revision_id = uuid::Uuid::now_v7().to_string();
    current(&f, &pause, proto::ProxyDesiredState::Paused);
    let paused = client
        .reconcile_runtime(pause.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        paused.observed_state,
        i32::from(proto::ProxyObservedState::Paused)
    );
    assert_eq!(
        paused.runtime.unwrap().target,
        first.target,
        "cleanup must use older immutable launch without new revision profile"
    );
    let retire = new_operation(pause);
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    let removed = client
        .reconcile_runtime(retire.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        removed.observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert!(removed.runtime.is_none());
    assert_eq!(fs::read_dir(root.join("staging")).unwrap().count(), 1);
    assert_eq!(
        client
            .reconcile_runtime(retire)
            .await
            .unwrap()
            .into_inner()
            .observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    current(&f, &second, proto::ProxyDesiredState::Serving);
    let again = client
        .reconcile_runtime(second.clone())
        .await
        .unwrap()
        .into_inner()
        .runtime
        .unwrap();
    assert_eq!(again.runtime_id, two.runtime_id);
    assert!(!again.ready && !again.admitting);
    assert!(root.join("material/m1").exists());
    let retire = new_operation(second);
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    assert_eq!(
        client
            .reconcile_runtime(retire)
            .await
            .unwrap()
            .into_inner()
            .observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert_eq!(fs::read_dir(root.join("staging")).unwrap().count(), 0);
    drop(client);
    agent.stop();
    eprintln!("TASK3A two-proxy cleanup evidence root={}", root.display());
    f.stop().await;
}
