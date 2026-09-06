//! Actual production retry after simulated lost per-proxy attachment persistence.
use super::*;

fn case(f: &Fixture) -> PathBuf {
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4n-{}", uuid::Uuid::now_v7()));
    setup(&root, f);
    enable(&root);
    // Native ELF, never a successful verification double. A legacy fallback
    // reaches SIGNATURE_REFUSED promptly without signing/pulling any image.
    fs::copy("/usr/bin/false", root.join("refuse-signature")).unwrap();
    fs::set_permissions(
        root.join("refuse-signature"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    root
}
fn no_effects(root: &Path) {
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    for entry in fs::read_dir(root.join("journal")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|v| v == "json")
            && path.file_name().unwrap() != "network-reservations.json"
        {
            let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let i = &v["record"]["installed"];
            assert_eq!(i["phase"], "Intent");
            assert_eq!(i["image_id"], "");
            assert_eq!(i["container_id"], "");
            assert_eq!(i["files"], json!({}));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit owned-volume Linux production binary fixture; no signing"]
async fn actual_orphan_opt_out_restart_never_falls_back_to_legacy_effects() {
    let f = Fixture::start().await;
    let mut request = request();
    current(&f, &request, proto::ProxyDesiredState::Serving);
    let root = case(&f);
    let (agent, mut client) = start_mode(&root, &f, true).await;
    assert_eq!(
        client
            .reconcile_runtime(request.clone())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_ENGINE_REFUSED" // No real outer fabric in this reservation fixture.
    );
    let original = assert_reserved(&root);
    drop(client);
    agent.stop();
    let global = fs::read(root.join("journal/network-reservations.json")).unwrap();
    crate::execution::fixture_network_attachment_gap(
        &root,
        INSTALL,
        request.target.as_ref().unwrap(),
    );
    // Exact committed-global + old per-proxy durable state, using genuine checksum.
    assert_eq!(
        fs::read(root.join("journal/network-reservations.json")).unwrap(),
        global
    );
    for opt_in in [false, true, false] {
        request.command_id = uuid::Uuid::now_v7().to_string();
        request.target.as_mut().unwrap().fencing_token += 1;
        current(&f, &request, proto::ProxyDesiredState::Serving);
        let (agent, mut client) = start_mode(&root, &f, opt_in).await;
        let error = client.reconcile_runtime(request.clone()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(
            error.message(),
            if opt_in {
                "RUNTIME_ENGINE_REFUSED"
            } else {
                "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
            },
            "lost attachment must not select signature/legacy effects after opt-out"
        );
        no_effects(&root);
        assert_eq!(
            fs::read(root.join("journal/network-reservations.json")).unwrap(),
            global
        );
        if opt_in {
            assert_eq!(assert_reserved(&root)["installed"], original["installed"]);
        }
        drop(client);
        agent.stop();
    }
    eprintln!("TASK4N simulated attachment-gap root={}", root.display());
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit owned-volume Linux production binary fixture; no signing"]
async fn actual_unreserved_legacy_reaches_signature_boundary() {
    let f = Fixture::start().await;
    let r = request();
    current(&f, &r, proto::ProxyDesiredState::Serving);
    for ingress in [false, true] {
        let root = case(&f);
        if !ingress {
            catalogs(&root.join("config"), &f); // Genuine schema1 positive control.
        }
        let (agent, mut client) = start_mode(&root, &f, false).await;
        assert_eq!(
            client
                .reconcile_runtime(r.clone())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_SIGNATURE_REFUSED"
        );
        assert!(!root.join("journal/network-reservations.json").exists());
        no_effects(&root);
        drop(client);
        agent.stop();
        eprintln!("TASK4N unreserved legacy boundary root={}", root.display());
    }
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit owned-volume Linux production binary fixture; no signing"]
async fn actual_opt_out_refuses_corrupt_and_incomplete_global_history() {
    let f = Fixture::start().await;
    let mut r = request();
    current(&f, &r, proto::ProxyDesiredState::Serving);
    for incomplete in [false, true] {
        let root = case(&f);
        let (agent, mut client) = start_mode(&root, &f, true).await;
        assert_eq!(
            client
                .reconcile_runtime(r.clone())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_ENGINE_REFUSED" // Task4P read-only inventory requires real fabric.
        );
        drop(client);
        agent.stop();
        crate::execution::fixture_network_attachment_gap(
            &root,
            INSTALL,
            r.target.as_ref().unwrap(),
        );
        // Faults touch only this freshly created case, never retained prior history.
        let name = if incomplete {
            "network-reservations.json.next"
        } else {
            "network-reservations.json"
        };
        write(&root.join("journal"), name, b"[]");
        r.command_id = uuid::Uuid::now_v7().to_string();
        r.target.as_mut().unwrap().fencing_token += 1;
        current(&f, &r, proto::ProxyDesiredState::Serving);
        let (agent, mut client) = start_mode(&root, &f, false).await;
        assert_eq!(
            client
                .reconcile_runtime(r.clone())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_NETWORK_RESERVATION_REFUSED"
        );
        no_effects(&root);
        assert_eq!(fs::read(root.join("journal").join(name)).unwrap(), b"[]");
        drop(client);
        agent.stop();
        eprintln!(
            "TASK4N simulated corrupt/incomplete history root={}",
            root.display()
        );
    }
    f.stop().await;
}
