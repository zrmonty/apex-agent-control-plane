//! Private scheduling around the production owner, real mTLS/Cosign/Docker/FS.
use super::*;
mod predispatch;
mod proof;
mod retention;
mod revocation;
use crate::{
    config::{Directory, deployment::Deployment},
    execution::testing::{Hooks, Point},
};
struct Running {
    client: RuntimeExecutionServiceClient<tonic::transport::Channel>,
    hooks: Arc<Hooks>,
    reader: owner::Reader,
    shutdown: watch::Sender<bool>,
    serving: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}
impl Running {
    async fn start(root: &Path, f: &Fixture) -> Self {
        let addr = configure(root, f);
        let path = root.join("config");
        let (deployment, _) = Deployment::load(&Directory::open(&path).unwrap(), None).unwrap();
        let hooks = Arc::clone(&deployment.resources.as_ref().unwrap().hooks);
        let fingerprint = deployment.fingerprint;
        let reader = owner::Reader::start(move || {
            Deployment::load(&Directory::open(&path)?, Some(fingerprint)).map(|(_, m)| m)
        })
        .unwrap();
        let authority = RuntimeAuthorityClient::connect(deployment.authority_config())
            .await
            .unwrap();
        let (shutdown, mut stopped) = watch::channel(false);
        let (router, incoming) = super::super::super::startup::prepare_listener(
            deployment,
            authority,
            Arc::clone(&reader.shared),
            stopped.clone(),
            reader.publication.clone(),
        )
        .await
        .unwrap();
        let serving = tokio::spawn(router.serve_with_incoming_shutdown(incoming, async move {
            let _ = stopped.changed().await;
        }));
        let tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
            .identity(f.pki.identity("trusted-host", CONTROLLER));
        let channel = Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            client: RuntimeExecutionServiceClient::new(channel).max_decoding_message_size(16_384),
            hooks,
            reader,
            shutdown,
            serving,
        }
    }
    async fn stop(self) {
        drop(self.client);
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(15), self.serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(self.reader);
    }
}
fn root(f: &Fixture) -> PathBuf {
    current(f, &request(), proto::ProxyDesiredState::Serving);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("boundary-{}", uuid::Uuid::now_v7()));
    setup(&root, f);
    root
}
fn record(root: &Path) -> serde_json::Value {
    let file = fs::read_dir(root.join("journal"))
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.path().extension().is_some_and(|s| s == "json"))
        .unwrap();
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(file.path()).unwrap()).unwrap();
    envelope["record"].clone()
}
fn stage(root: &Path, r: &serde_json::Value) -> PathBuf {
    root.join("staging")
        .join(format!("apex-runtime-{}", r["instance"].as_str().unwrap()))
}
async fn interrupt(running: &Running, request: proto::RuntimeReconcileRequest, point: Point) {
    let mut gate = running.hooks.arm(point);
    let mut client = running.client.clone();
    let job = tokio::spawn(async move { client.reconcile_runtime(request).await });
    tokio::time::timeout(Duration::from_secs(60), &mut gate.reached)
        .await
        .unwrap()
        .unwrap();
    gate.release(true);
    assert!(
        job.await.unwrap().is_err(),
        "interruption must not report completion"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_persisted_stage_and_create_boundaries_recover_or_quarantine() {
    for (point, recover) in [
        (Point::ProofIntent, false),
        (Point::StageIntent, false),
        (Point::StageFile, false),
        (Point::Sealed, true),
        (Point::CreateIntent, false),
        (Point::Created, true),
    ] {
        let f = Fixture::start().await;
        let root = root(&f);
        let running = Running::start(&root, &f).await;
        interrupt(&running, request(), point).await;
        running.stop().await;
        let before = record(&root);
        let staged = stage(&root, &before);
        let unknown = root.join("staging/unknown-preserve");
        fs::create_dir(&unknown).unwrap();
        write(&unknown, "evidence", b"unknown-resource");
        if point == Point::StageFile {
            assert_eq!(fs::read_dir(&staged).unwrap().count(), 1);
            write(&staged, "unknown", b"never-delete");
        }
        let mut next = request();
        next.command_id = uuid::Uuid::now_v7().to_string();
        next.target.as_mut().unwrap().fencing_token += 1;
        current(&f, &next, proto::ProxyDesiredState::Serving);
        let (agent, mut client) = start(&root, &f).await;
        let result = client.reconcile_runtime(next.clone()).await;
        if recover {
            let reply = result.unwrap().into_inner();
            assert_eq!(
                reply.observed_state,
                i32::from(proto::ProxyObservedState::NotServing)
            );
            let runtime = reply.runtime.unwrap();
            assert_eq!(runtime.target, request().target);
            assert!(!runtime.ready && !runtime.admitting);
            let retire = new_operation(next);
            current(&f, &retire, proto::ProxyDesiredState::Retired);
            assert!(
                client
                    .reconcile_runtime(retire)
                    .await
                    .unwrap()
                    .into_inner()
                    .runtime
                    .is_none()
            );
        } else {
            assert!(
                result.is_err(),
                "uncertain partial stage/create cannot be blindly recreated"
            );
        }
        drop(client);
        agent.stop();
        let after = record(&root);
        assert_eq!(before["instance"], after["instance"]);
        assert_eq!(before["original"], after["original"]);
        assert_eq!(
            before["installed"]["launch_json"],
            after["installed"]["launch_json"]
        );
        if !recover {
            assert_eq!(before["installed"], after["installed"]);
        }
        assert_eq!(
            fs::read(unknown.join("evidence")).unwrap(),
            b"unknown-resource"
        );
        if point == Point::StageFile {
            assert_eq!(fs::read(staged.join("unknown")).unwrap(), b"never-delete");
        }
        assert!(root.join("material/m1").exists());
        eprintln!(
            "TASK3A persisted boundary {point:?} recovery={recover} root={}",
            root.display()
        );
        f.stop().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_removal_boundaries_and_partial_cleanup_preserve_unknown() {
    for point in [Point::RemoveIntent, Point::Removed, Point::StageUnlink] {
        let f = Fixture::start().await;
        let root = root(&f);
        let running = Running::start(&root, &f).await;
        let mut client = running.client.clone();
        client.reconcile_runtime(request()).await.unwrap();
        let before = record(&root);
        let retire = new_operation(request());
        current(&f, &retire, proto::ProxyDesiredState::Retired);
        interrupt(&running, retire.clone(), point).await;
        drop(client);
        running.stop().await;
        let staged = stage(&root, &before);
        if point == Point::StageUnlink {
            assert_eq!(
                fs::read_dir(&staged).unwrap().count(),
                before["installed"]["files"].as_object().unwrap().len() - 1
            );
            write(&staged, "unknown", b"preserve-unknown");
            let (agent, mut client) = start(&root, &f).await;
            let count = fs::read_dir(&staged).unwrap().count();
            assert_eq!(
                client
                    .reconcile_runtime(retire.clone())
                    .await
                    .unwrap_err()
                    .message(),
                "RUNTIME_MATERIAL_CLEANUP_PENDING"
            );
            assert_eq!(fs::read_dir(&staged).unwrap().count(), count);
            assert_eq!(
                fs::read(staged.join("unknown")).unwrap(),
                b"preserve-unknown"
            );
            drop(client);
            agent.stop();
            // Fixture owner withdraws only its injected file; agent never removes it.
            fs::remove_file(staged.join("unknown")).unwrap();
        }
        let (agent, mut client) = start(&root, &f).await;
        let reply = client.reconcile_runtime(retire).await.unwrap().into_inner();
        assert_eq!(
            reply.observed_state,
            i32::from(proto::ProxyObservedState::Retired)
        );
        assert!(reply.runtime.is_none());
        drop(client);
        agent.stop();
        assert!(!staged.exists());
        let after = record(&root);
        assert_eq!(before["instance"], after["instance"]);
        assert_eq!(before["original"], after["original"]);
        assert!(root.join("material/m1").exists());
        eprintln!("TASK3A removal boundary {point:?} root={}", root.display());
        f.stop().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_held_preflight_expiry_launches_zero_children_retains_proxy() {
    let f = Fixture::start().await;
    let root = root(&f);
    let running = Running::start(&root, &f).await;
    let mut gate = running.hooks.arm(Point::Preflight);
    let mut client = running.client.clone();
    let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
    let deadline = tokio::time::timeout(Duration::from_secs(40), &mut gate.reached)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let before = running.hooks.count(Point::Spawn); // Signature child completed before engine preflight.
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        deadline + Duration::from_millis(10),
    ))
    .await;
    let mut client = running.client.clone();
    assert_eq!(
        client
            .reconcile_runtime(request())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_PROXY_BUSY"
    );
    assert_eq!(running.hooks.count(Point::Spawn), before);
    gate.release(false);
    let result = job.await.unwrap();
    assert_eq!(
        running.hooks.count(Point::Spawn),
        before,
        "expired preflight must never dispatch child"
    );
    assert_eq!(
        result.unwrap_err().message(),
        "RUNTIME_ENGINE_COMMAND_DEADLINE"
    );
    running.stop().await;
    eprintln!("TASK3A held preflight root={}", root.display());
    f.stop().await;
}
