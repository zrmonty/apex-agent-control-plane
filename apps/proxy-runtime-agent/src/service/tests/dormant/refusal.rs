//! Actual negative effect gates, scoped durable evidence retained on failure.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_bad_signature_and_material_never_create_a_container() {
    let f = Fixture::start().await;
    current(&f, &request(), proto::ProxyDesiredState::Serving);
    let base = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap());
    for signature in [true, false] {
        let root = base.join(format!("refusal-{}", uuid::Uuid::now_v7()));
        setup(&root, &f);
        if signature {
            let path = root.join("config/image-catalog.json");
            let mut image: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            image["images"][0]["signing"]["certificate_identity"] =
                "not-the-approved-signer@example.com".into();
            write(
                &root.join("config"),
                "image-catalog.json",
                &serde_json::to_vec(&image).unwrap(),
            );
        } else {
            write(&root.join("material"), "m1", b"invalid-health-token");
        }
        let (agent, mut client) = start(&root, &f).await;
        let error = client.reconcile_runtime(request()).await.unwrap_err();
        assert_eq!(
            error.message(),
            if signature {
                "RUNTIME_SIGNATURE_REFUSED"
            } else {
                "RUNTIME_STAGE_REFUSED"
            }
        );
        assert_eq!(fs::read_dir(root.join("staging")).unwrap().count(), 0);
        drop(client);
        agent.stop();
        let path = fs::read_dir(root.join("journal"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .unwrap();
        let journal: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let instance = journal["record"]["instance"].as_str().unwrap();
        assert!(crate::shapes::uuid_v7(instance));
        let output = Command::new("/apex-engine-tools/docker")
            .args([
                "--host=unix:///run/apex-docker.sock",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                &format!("--filter=name=^/apex-runtime-{instance}$"),
                "--format={{.ID}}",
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.iter().all(u8::is_ascii_whitespace));
        eprintln!(
            "TASK3A refused signature={signature} evidence root={}",
            root.display()
        );
    }
    f.stop().await;
}
