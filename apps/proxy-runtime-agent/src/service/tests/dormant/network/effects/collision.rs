use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Task4P foreign overlapping NEW fixture preserved by actual production agent"]
async fn actual_foreign_overlap_never_adopts_or_reassigns() {
    let f = Fixture::start().await;
    let req = request();
    bind(&f, &req);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4p-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    let name = format!("apex-task4p-foreign-{}", uuid::Uuid::now_v7());
    let out = Command::new("/apex-engine-tools/docker")
        .arg("--host=unix:///run/apex-docker.sock")
        .args([
            "network",
            "create",
            "--driver=bridge",
            "--internal",
            "--subnet=10.248.0.0/24",
            "--label",
        ])
        .arg(format!("apex.fixture.owner={name}"))
        .arg(&name)
        .output()
        .unwrap();
    assert!(out.status.success());
    let id = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let original = docker(&["network", "inspect", &id]);
    let (agent, mut client) = start_network(&root, &f).await;
    assert!(client.reconcile_runtime(req.clone()).await.is_err());
    drop(client);
    agent.stop();
    assert!(documents_at(&root).is_empty());
    assert_reserved(&root);
    let (agent, mut client) = start_mode(&root, &f, false).await;
    assert_eq!(
        client.reconcile_runtime(req).await.unwrap_err().message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    drop(client);
    agent.stop();
    let actual = docker(&["network", "inspect", &id]);
    assert_eq!(actual, original);
    assert_eq!(actual[0]["Id"], id);
    assert_eq!(actual[0]["Labels"]["apex.fixture.owner"], name);
    assert_eq!(actual[0]["Containers"], json!({}));
    assert!(
        Command::new("/apex-engine-tools/docker")
            .arg("--host=unix:///run/apex-docker.sock")
            .args(["network", "rm", &id])
            .status()
            .unwrap()
            .success()
    );
    eprintln!("TASK4P collision root={}", root.display());
    f.stop().await;
}
