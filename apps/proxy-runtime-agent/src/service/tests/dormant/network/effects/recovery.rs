use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Task4P actual two-proxy empty networks/restart/opt-out/fault simulation in new owned root"]
async fn actual_two_proxy_restart_optout_and_original_intent_adoption() {
    let f = Fixture::start().await;
    let mut first = request();
    bind(&f, &first);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4p-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let mut second = request();
    second.target.as_mut().unwrap().proxy_id = uuid::Uuid::now_v7().to_string();
    second.operation_id = uuid::Uuid::now_v7().to_string();
    second.command_id = uuid::Uuid::now_v7().to_string();
    bind(&f, &second);
    catalogs(&root.join("config"), &f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    fs::remove_file(root.join("material/m1")).unwrap();
    let (agent, mut a) = start_network(&root, &f).await;
    let mut b = a.clone();
    let (x, y) = tokio::join!(
        a.reconcile_runtime(first.clone()),
        b.reconcile_runtime(second.clone())
    );
    assert_eq!(
        x.unwrap_err().message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    assert_eq!(
        y.unwrap_err().message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    drop(a);
    drop(b);
    agent.stop();
    let original = documents_at(&root);
    assert_eq!(original.len(), 2);
    let ids: std::collections::BTreeSet<_> = original
        .iter()
        .map(|(_, v)| v["document"]["observation"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    let subnets: std::collections::BTreeSet<_> = original
        .iter()
        .map(|(_, v)| {
            v["document"]["topology"]["internal_subnet"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(
        subnets,
        std::collections::BTreeSet::from(["10.248.0.0/29", "10.248.0.8/29"])
    );
    let (agent, mut client) = start_mode(&root, &f, false).await;
    for r in [&first, &second] {
        assert_eq!(
            client
                .reconcile_runtime(r.clone())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
        );
    }
    drop(client);
    agent.stop();
    assert_eq!(documents_at(&root), original);
    for r in [&mut first, &mut second] {
        r.command_id = uuid::Uuid::now_v7().to_string();
        r.target.as_mut().unwrap().fencing_token += 1;
        bind(&f, r);
    }
    let (agent, mut client) = start_network(&root, &f).await;
    for r in [&first, &second] {
        assert_eq!(
            client
                .reconcile_runtime(r.clone())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
        );
    }
    drop(client);
    agent.stop();
    assert_eq!(documents_at(&root), original);
    // Restore only the durable CreateIntent equivalent under this NEW per-test root.
    // Real network remains; genuine typed checksum is recomputed. Not power loss.
    crate::execution::fixture_network_lost_observation(
        &root,
        INSTALL,
        first.target.as_ref().unwrap(),
    );
    let (agent, mut client) = start_network(&root, &f).await;
    assert_eq!(
        client
            .reconcile_runtime(first.clone())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    drop(client);
    agent.stop();
    assert_eq!(documents_at(&root), original);
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    // Cleanup is not implemented; changed current state must retain every network.
    let pause = new_operation(first);
    current(&f, &pause, proto::ProxyDesiredState::Paused);
    f.callback.targets.lock().unwrap().insert(
        pause.target.as_ref().unwrap().proxy_id.clone(),
        f.callback.reply.lock().unwrap().clone(),
    );
    let (agent, mut client) = start_network(&root, &f).await;
    assert_eq!(
        client.reconcile_runtime(pause).await.unwrap_err().message(),
        "RUNTIME_NETWORK_CLEANUP_PENDING"
    );
    drop(client);
    agent.stop();
    assert_eq!(documents_at(&root), original);
    for (_, v) in &original {
        remove_owned(v);
    }
    eprintln!("TASK4P two-proxy root={}", root.display());
    f.stop().await;
}
