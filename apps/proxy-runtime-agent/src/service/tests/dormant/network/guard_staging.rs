//! Controller-run native refusal only: actual Cosign, no positive signing seam.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Task4W controller-owned native window; actual network-none Cosign refusal"]
async fn task4w_production_signature_refusal_precedes_guard_intent_and_files() {
    let f = Fixture::start().await;
    let req = request();
    bind(&f, &req);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4w-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    let path = root.join("config/network-catalog.json");
    let mut n: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    n["profiles"][0]["grants"][2] = json!({"purpose":"upstream",
        "host":"portfolio-api.apex.test","port":443,"cidrs":["8.8.8.0/24"]});
    write(
        &root.join("config"),
        "network-catalog.json",
        &serde_json::to_vec(&n).unwrap(),
    );
    // Guard staging has no reason to read workload secrets.
    fs::remove_file(root.join("material/m1")).unwrap();
    for _ in 0..2 {
        let (agent, mut client) = start_network(&root, &f).await;
        let error = client.reconcile_runtime(req.clone()).await.unwrap_err();
        assert_eq!(error.message(), "RUNTIME_SIGNATURE_REFUSED");
        drop(client);
        agent.stop();
        let records: Vec<Value> = fs::read_dir(root.join("journal"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|path| serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap())
            .filter_map(|value| value.get("record").cloned())
            .collect();
        assert_eq!(records.len(), 1);
        let installed = &records[0]["installed"];
        assert!(installed.get("guard_stage").is_none());
        assert_eq!(installed["phase"], "Intent");
        assert_eq!(installed["files"], json!({}));
        assert_eq!(installed["image_id"], "");
        assert_eq!(installed["container_id"], "");
        assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
        let docs = documents_at(&root);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].1["document"]["phase"], "Observed");
        let id = docs[0].1["document"]["observation"].as_str().unwrap();
        assert_eq!(
            docker(&["network", "inspect", id])[0]["Containers"],
            json!({})
        );
    }
    for (_, document) in documents_at(&root) {
        remove_owned(&document);
    }
    eprintln!(
        "TASK4W signature-refusal root={} outer={}",
        root.display(),
        fabric.id
    );
    drop(fabric);
    f.stop().await;
}
