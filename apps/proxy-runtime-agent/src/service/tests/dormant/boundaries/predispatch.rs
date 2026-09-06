//! An ordinary pre-dispatch refusal is not an unknown Docker completion.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_predispatch_superseding_cleanup_never_needs_create() {
    for desired in [
        proto::ProxyDesiredState::Paused,
        proto::ProxyDesiredState::Retired,
    ] {
        let f = Fixture::start().await;
        let root = root(&f);
        let running = Running::start(&root, &f).await;
        let mut gate = running.hooks.arm(Point::CreateIntent);
        let mut client = running.client.clone();
        let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
        tokio::time::timeout(Duration::from_secs(60), &mut gate.reached)
            .await
            .unwrap()
            .unwrap();
        let before = record(&root);
        let cleanup = new_operation(request());
        current(&f, &cleanup, desired);
        let spawned = running.hooks.count(Point::Spawn);
        gate.release(false);
        assert_eq!(
            job.await.unwrap().unwrap_err().message(),
            "RUNTIME_AUTHORITY_REFUSED"
        );
        assert_eq!(running.hooks.count(Point::Spawn), spawned);
        assert_eq!(running.hooks.count(Point::Created), 0);
        assert_eq!(record(&root)["installed"]["phase"], "Staged");
        running.stop().await;

        // Never restore Serving: the superseding cleanup stays authoritative.
        let expected = if desired == proto::ProxyDesiredState::Paused {
            proto::ProxyObservedState::Paused
        } else {
            proto::ProxyObservedState::Retired
        };
        for _ in 0..2 {
            let (agent, mut client) = start(&root, &f).await;
            let result = client
                .reconcile_runtime(cleanup.clone())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(result.claims, Some(cleanup.clone()));
            assert_eq!(result.observed_state, i32::from(expected));
            assert!(
                result.runtime.is_none(),
                "no fabricated container observation"
            );
            drop(client);
            agent.stop();
        }
        if desired == proto::ProxyDesiredState::Paused {
            assert!(
                stage(&root, &before).exists(),
                "pause preserves sealed stage"
            );
            assert_eq!(record(&root)["installed"]["phase"], "Staged");
            let retire = new_operation(cleanup);
            current(&f, &retire, proto::ProxyDesiredState::Retired);
            let (agent, mut client) = start(&root, &f).await;
            let result = client.reconcile_runtime(retire).await.unwrap().into_inner();
            assert_eq!(
                result.observed_state,
                i32::from(proto::ProxyObservedState::Retired)
            );
            assert!(result.runtime.is_none());
            drop(client);
            agent.stop();
        }
        assert_eq!(record(&root)["instance"], before["instance"]);
        assert_eq!(record(&root)["original"], before["original"]);
        assert!(!stage(&root, &before).exists());
        assert!(root.join("material/m1").exists());
        eprintln!(
            "TASK3B predispatch superseding {desired:?} root={}",
            root.display()
        );
        f.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_predispatch_authority_refusal_retries_same_instance() {
    let f = Fixture::start().await;
    let root = root(&f);
    let running = Running::start(&root, &f).await;
    let mut gate = running.hooks.arm(Point::CreateIntent);
    let mut client = running.client.clone();
    let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
    tokio::time::timeout(Duration::from_secs(60), &mut gate.reached)
        .await
        .unwrap()
        .unwrap();
    let before = record(&root);
    assert_eq!(before["installed"]["phase"], "CreateIntent");
    let spawned = running.hooks.count(Point::Spawn);
    // The actual authenticated callback now echoes a different operation. The
    // scheduling hook itself succeeds: this is refusal, not a simulated crash.
    current(
        &f,
        &new_operation(request()),
        proto::ProxyDesiredState::Serving,
    );
    gate.release(false);
    assert_eq!(
        job.await.unwrap().unwrap_err().message(),
        "RUNTIME_AUTHORITY_REFUSED"
    );
    assert_eq!(running.hooks.count(Point::Spawn), spawned);
    assert_eq!(running.hooks.count(Point::Created), 0);
    let after = record(&root);
    assert_eq!(after["installed"]["phase"], "Staged");
    let mut expected = before.clone();
    expected["installed"]["phase"] = "Staged".into();
    assert!(
        after == expected,
        "only proven no-dispatch phase may change"
    );
    running.stop().await;

    // A separately compiled production owner must consume the durable fact.
    current(&f, &request(), proto::ProxyDesiredState::Serving);
    let (agent, mut client) = start(&root, &f).await;
    let installed = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(installed.claims, Some(request()));
    assert_eq!(
        installed.observed_state,
        i32::from(proto::ProxyObservedState::NotServing)
    );
    let runtime = installed.runtime.unwrap();
    assert_eq!(runtime.target, request().target);
    assert!(!runtime.ready && !runtime.admitting);
    assert_eq!(record(&root)["instance"], before["instance"]);
    let again = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.runtime.unwrap().runtime_id, runtime.runtime_id);
    drop(client);
    agent.stop();
    let (agent, mut client) = start(&root, &f).await;
    let again = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.runtime.unwrap().runtime_id, runtime.runtime_id);
    let retire = new_operation(request());
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    let retired = client.reconcile_runtime(retire).await.unwrap().into_inner();
    assert_eq!(
        retired.observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert!(retired.runtime.is_none());
    assert!(!stage(&root, &before).exists());
    assert!(root.join("material/m1").exists());
    drop(client);
    agent.stop();
    eprintln!("TASK3A proven predispatch recovery root={}", root.display());
    f.stop().await;
}
