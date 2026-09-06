use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_poison_revocation_and_changed_authority_stop_later_effects() {
    for scenario in 0..3 {
        let f = Fixture::start().await;
        let root = root(&f);
        let original_tools = fs::read(root.join("config/tool-bindings.json")).unwrap();
        let running = Running::start(&root, &f).await;
        let point = if scenario == 0 {
            Point::Sealed
        } else {
            Point::Created
        };
        let mut gate = running.hooks.arm(point);
        let original_metadata = owner::snapshot(&running.reader.shared).unwrap();
        let mut client = running.client.clone();
        let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
        tokio::time::timeout(Duration::from_secs(60), &mut gate.reached)
            .await
            .unwrap()
            .unwrap();
        let spawned = running.hooks.count(Point::Spawn);
        match scenario {
            0 => write(&root.join("config"), "tool-bindings.json", b"{poison"),
            1 => {
                let path = root.join("config/peer-policy.json");
                let mut policy: serde_json::Value =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                for peer in policy["peers"].as_array_mut().unwrap() {
                    peer["revoked"] = true.into();
                }
                write(
                    &root.join("config"),
                    "peer-policy.json",
                    &serde_json::to_vec(&policy).unwrap(),
                );
            }
            _ => current(&f, &request(), proto::ProxyDesiredState::Paused),
        }
        if scenario < 2 {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if owner::snapshot(&running.reader.shared)
                        .map_or(true, |m| !Arc::ptr_eq(&m, &original_metadata))
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        gate.release(false);
        assert!(job.await.unwrap().is_err());
        assert_eq!(
            running.hooks.count(Point::Spawn),
            spawned,
            "no later child after protected metadata or current authority changed"
        );
        running.stop().await;
        let before = record(&root);
        let staged = stage(&root, &before);
        assert!(staged.exists(), "revocation must not authorize cleanup");
        assert!(root.join("material/m1").exists());
        // Restore fixture-owned authority; restart has to prove original identity.
        current(&f, &request(), proto::ProxyDesiredState::Serving);
        write(&root.join("config"), "tool-bindings.json", &original_tools);
        catalogs(&root.join("config"), &f);
        let (agent, mut client) = start(&root, &f).await;
        let runtime = client
            .reconcile_runtime(request())
            .await
            .unwrap()
            .into_inner()
            .runtime
            .unwrap();
        assert_eq!(runtime.target, request().target);
        assert!(!runtime.ready && !runtime.admitting);
        let retire = new_operation(request());
        current(&f, &retire, proto::ProxyDesiredState::Retired);
        client.reconcile_runtime(retire).await.unwrap();
        drop(client);
        agent.stop();
        let after = record(&root);
        assert_eq!(before["instance"], after["instance"]);
        assert_eq!(before["original"], after["original"]);
        eprintln!(
            "TASK3A physical checkpoint authority scenario={scenario} root={}",
            root.display()
        );
        f.stop().await;
    }
}
