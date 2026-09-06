use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_130_retries_restart_fresh_cleanup_and_conflicting_replay() {
    let f = Fixture::start().await;
    let root = root(&f);
    let (mut agent, mut client) = start(&root, &f).await;
    let original = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner()
        .runtime
        .unwrap();
    let mut pause = new_operation(request());
    current(&f, &pause, proto::ProxyDesiredState::Paused);
    let first_pause = pause.clone();
    for n in 0..130 {
        pause.command_id = uuid::Uuid::now_v7().to_string();
        current(&f, &pause, proto::ProxyDesiredState::Paused);
        let r = client
            .reconcile_runtime(pause.clone())
            .await
            .unwrap()
            .into_inner()
            .runtime
            .unwrap();
        assert_eq!(r.runtime_id, original.runtime_id);
        assert_eq!(r.target, original.target);
        if n == 65 {
            drop(client);
            agent.stop();
            (agent, client) = start(&root, &f).await;
        }
    }
    let mut fresh = new_operation(pause.clone());
    current(&f, &fresh, proto::ProxyDesiredState::Paused);
    assert!(client.reconcile_runtime(fresh.clone()).await.is_ok());
    for old in [request(), first_pause, pause] {
        let mut conflict = fresh.clone();
        conflict.command_id = old.command_id;
        current(&f, &conflict, proto::ProxyDesiredState::Paused);
        assert!(
            client.reconcile_runtime(conflict).await.is_err(),
            "fresh authority cannot rebind old command ID"
        );
    }
    fresh = new_operation(fresh);
    current(&f, &fresh, proto::ProxyDesiredState::Retired);
    assert!(
        client
            .reconcile_runtime(fresh)
            .await
            .unwrap()
            .into_inner()
            .runtime
            .is_none()
    );
    drop(client);
    agent.stop();
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    assert!(root.join("material/m1").exists());
    assert_eq!(record(&root)["commands"].as_object().unwrap().len(), 64);
    eprintln!(
        "TASK3A 130 actual retries/restart/cleanup root={}",
        root.display()
    );
    f.stop().await;
}
