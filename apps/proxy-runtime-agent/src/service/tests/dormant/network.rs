//! Production binary + actual mTLS callback + real protected journal; no artifacts started.
use super::*;
use serde_json::{Value, json};
mod effects;
mod recovery;
fn enable(root: &Path) {
    let config = root.join("config");
    let mut a: Value =
        serde_json::from_slice(&fs::read(config.join("authority-profiles.json")).unwrap()).unwrap();
    a["schema_version"] = json!(3);
    a["profiles"][0]["mode"] = json!("managed_ingress");
    a["profiles"][0]["managed"] = json!({"evidence_agent_id":"managed-evidence","upstream_credentials":"managed_upstream_v1",
        "network_policy":{"reference":"net","version":"v1"},"ingress":{"port":8080,"tls_server_name":"gateway.example","edge_certificate_sha256":["a".repeat(64)]}});
    write(
        &config,
        "authority-profiles.json",
        &serde_json::to_vec(&a).unwrap(),
    );
    let mut n = crate::network_catalog::tests::fixture();
    n["host_policy_version"] = json!("host-1");
    // Existing approved public image is selection data only; it is never pulled or executed here.
    n["profiles"][0]["guard_image_catalog_id"] = json!("gateway");
    n["profiles"][0]["guard_image_ref"] = json!(IMAGE);
    write(
        &config,
        "network-catalog.json",
        &serde_json::to_vec(&n).unwrap(),
    );
}
async fn start_network(
    root: &Path,
    f: &Fixture,
) -> (
    Binary,
    RuntimeExecutionServiceClient<tonic::transport::Channel>,
) {
    start_mode(root, f, true).await
}
async fn start_mode(
    root: &Path,
    f: &Fixture,
    opt_in: bool,
) -> (
    Binary,
    RuntimeExecutionServiceClient<tonic::transport::Channel>,
) {
    let addr = configure(root, f);
    let config = root.join("config");
    let mut a: Value =
        serde_json::from_slice(&fs::read(config.join("agent.json")).unwrap()).unwrap();
    if opt_in {
        a["execution"]["network_profile"] = json!("isolated-bridge-v1");
    }
    if root.join("refuse-signature").is_file() {
        a["execution"]["cosign_executable"] = json!(root.join("refuse-signature"));
    }
    write(&config, "agent.json", &serde_json::to_vec(&a).unwrap());
    let mut child = Binary(
        Command::new("/binding-tests/task4n-agent")
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
            "production agent exited"
        );
        if let Ok(c) = Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(tls.clone())
            .unwrap()
            .connect()
            .await
        {
            return (child, RuntimeExecutionServiceClient::new(c));
        }
        assert!(Instant::now() < deadline, "production listener unavailable");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn assert_reserved(root: &Path) -> Value {
    let mut records = vec![];
    for path in fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|e| e.unwrap().path())
    {
        if path.extension().is_some_and(|s| s == "json")
            && path.file_name().unwrap() != "network-reservations.json"
        {
            records.push(serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap());
        }
    }
    assert_eq!(records.len(), 1);
    let record = &records[0]["record"];
    let i = &record["installed"];
    assert_eq!(i["phase"], "Intent");
    assert_eq!(i["image_id"], "");
    assert_eq!(i["container_id"], "");
    assert_eq!(i["files"], json!({}));
    assert_eq!(i["network"]["schema_version"], 1);
    assert_eq!(i["network"]["slot"], 0);
    let slots: Value =
        serde_json::from_slice(&fs::read(root.join("journal/network-reservations.json")).unwrap())
            .unwrap();
    let entries = slots["document"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["instance"], i["instance"]);
    assert_eq!(entries[0]["owner_hash"], i["network"]["owner_hash"]);
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    let instance = i["instance"].as_str().unwrap();
    assert!(crate::shapes::uuid_v7(instance));
    let args = [
        "--host=unix:///run/apex-docker.sock".to_owned(),
        "container".into(),
        "ls".into(),
        "--all".into(),
        format!("--filter=name=^/apex-runtime-{instance}$"),
        "--format={{.ID}}".into(),
        "--no-trunc".into(),
    ]
    .map(std::ffi::OsString::from);
    let bytes = crate::command::run(crate::command::CommandInput {
        executable: Path::new("/apex-engine-tools/docker"),
        arguments: &args,
        directory: root,
        home: None,
        budget: Duration::from_secs(5),
        cancelled: &std::sync::atomic::AtomicBool::new(false),
    })
    .unwrap();
    assert!(
        bytes.iter().all(u8::is_ascii_whitespace),
        "positive exact-name absence required"
    );
    record.clone()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/owned volume; no image execution"]
async fn actual_network_reservation_precedes_all_stage_and_container_effects() {
    let f = Fixture::start().await;
    let first = request();
    current(&f, &first, proto::ProxyDesiredState::Serving);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4n-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    enable(&root);
    fs::remove_file(root.join("material/m1")).unwrap();
    let (agent, mut client) = start_network(&root, &f).await;
    for _ in 0..2 {
        let e = client.reconcile_runtime(first.clone()).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unavailable);
        // This reservation fixture has no actual protected outer fabric. Task4P
        // reaches independent read-only inventory, never stage/container effects.
        assert_eq!(e.message(), "RUNTIME_ENGINE_REFUSED");
    }
    let original = assert_reserved(&root);
    drop(client);
    agent.stop();
    let mut next = first.clone();
    next.command_id = uuid::Uuid::now_v7().to_string();
    next.target.as_mut().unwrap().fencing_token += 1;
    current(&f, &next, proto::ProxyDesiredState::Serving);
    let (agent, mut client) = start_network(&root, &f).await;
    let e = client.reconcile_runtime(next).await.unwrap_err();
    assert_eq!(e.message(), "RUNTIME_ENGINE_REFUSED");
    let recovered = assert_reserved(&root);
    assert_eq!(recovered["installed"], original["installed"]);
    drop(client);
    agent.stop();
    eprintln!("TASK4N reservation-only evidence root={}", root.display());
    f.stop().await;
}
