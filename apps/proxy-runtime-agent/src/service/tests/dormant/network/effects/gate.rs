//! Actual production composition with private scheduling, real TLS and Docker.
use super::*;
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
        let mut a: Value =
            serde_json::from_slice(&fs::read(path.join("agent.json")).unwrap()).unwrap();
        a["execution"]["network_profile"] = json!("isolated-bridge-v1");
        write(&path, "agent.json", &serde_json::to_vec(&a).unwrap());
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
        let (router, incoming) = crate::service::startup::prepare_listener(
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
            client: RuntimeExecutionServiceClient::new(channel),
            hooks,
            reader,
            shutdown,
            serving,
        }
    }
    async fn stop(self) {
        drop(self.client);
        self.shutdown.send(true).unwrap();
        self.serving.await.unwrap().unwrap();
        drop(self.reader);
    }
}
fn root(f: &Fixture) -> PathBuf {
    bind(f, &request());
    let p = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4p-{}", uuid::Uuid::now_v7()));
    setup(&p, f);
    p
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Task4P private final-spawn gate with actual production TLS/engine/journal"]
async fn actual_current_authority_is_rechecked_after_native_preflight() {
    let f = Fixture::start().await;
    let root = root(&f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    let running = Running::start(&root, &f).await;
    let mut gate = running.hooks.arm(Point::NetworkSpawn);
    let mut client = running.client.clone();
    let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
    tokio::time::timeout(Duration::from_secs(10), &mut gate.reached)
        .await
        .unwrap()
        .unwrap();
    f.callback
        .targets
        .lock()
        .unwrap()
        .get_mut(&request().target.unwrap().proxy_id)
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .desired_state = proto::ProxyDesiredState::Paused.into();
    gate.release(false);
    assert!(job.await.unwrap().is_err());
    assert_eq!(
        running.hooks.count(Point::NetworkChild),
        0,
        "revoked final gate must not attempt native spawn"
    );
    assert_eq!(documents_at(&root)[0].1["document"]["phase"], "Prepared");
    bind(&f, &request());
    let mut client = running.client.clone();
    assert_eq!(
        client
            .reconcile_runtime(request())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    drop(client);
    running.stop().await;
    for (_, v) in documents_at(&root) {
        remove_owned(&v);
    }
    eprintln!("TASK4P final-gate root={}", root.display());
    f.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Task4P actual child held before reap; final callback shortens lease"]
async fn actual_shortened_final_lease_bounds_native_command_completion() {
    let f = Fixture::start().await;
    let root = root(&f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    let running = Running::start(&root, &f).await;
    let mut spawn = running.hooks.arm(Point::NetworkSpawn);
    let mut client = running.client.clone();
    let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
    tokio::time::timeout(Duration::from_secs(10), &mut spawn.reached)
        .await
        .unwrap()
        .unwrap();
    let mut child = running.hooks.arm(Point::NetworkChild);
    {
        let mut targets = f.callback.targets.lock().unwrap();
        let a = targets
            .get_mut(&request().target.unwrap().proxy_id)
            .unwrap()
            .authority
            .as_mut()
            .unwrap();
        a.lease_expires_at_unix_us = a.checked_at_unix_us + 100_000;
    }
    spawn.release(false);
    tokio::time::timeout(Duration::from_secs(10), &mut child.reached)
        .await
        .unwrap()
        .unwrap();
    // This is an actual spawned native Docker child, deliberately retained unreaped.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!job.is_finished());
    assert_eq!(
        running
            .client
            .clone()
            .reconcile_runtime(request())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_PROXY_BUSY"
    );
    child.release(false);
    assert!(job.await.unwrap().is_err());
    let returned = running.hooks.count(Point::NetworkCommandReturned);
    assert_eq!(
        documents_at(&root)[0].1["document"]["phase"],
        "CreateIntent"
    );
    bind(&f, &request());
    let mut client = running.client.clone();
    assert_eq!(
        client
            .reconcile_runtime(request())
            .await
            .unwrap_err()
            .message(),
        "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
    );
    drop(client);
    running.stop().await;
    for (_, v) in documents_at(&root) {
        remove_owned(&v);
    }
    eprintln!("TASK4P shortened-lease root={}", root.display());
    f.stop().await;
    assert_eq!(
        returned, 0,
        "expired final lease must not return native command success"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Task4P durable intent/created interruption; restart uses actual production binary"]
async fn actual_intent_absence_is_uncertain_but_created_identity_recovers() {
    for point in [Point::NetworkIntent, Point::NetworkCreated] {
        let f = Fixture::start().await;
        let root = root(&f);
        let fabric = Fabric::new();
        fabric.configure(&root);
        let running = Running::start(&root, &f).await;
        let mut gate = running.hooks.arm(point);
        let mut client = running.client.clone();
        let job = tokio::spawn(async move { client.reconcile_runtime(request()).await });
        tokio::time::timeout(Duration::from_secs(10), &mut gate.reached)
            .await
            .unwrap()
            .unwrap();
        gate.release(true);
        assert!(job.await.unwrap().is_err());
        running.stop().await;
        assert_eq!(
            documents_at(&root)[0].1["document"]["phase"],
            "CreateIntent"
        );
        let (agent, mut client) = start_network(&root, &f).await;
        let error = client.reconcile_runtime(request()).await.unwrap_err();
        drop(client);
        agent.stop();
        let docs = documents_at(&root);
        if point == Point::NetworkCreated {
            assert_eq!(error.message(), "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE");
            assert_eq!(docs[0].1["document"]["phase"], "Observed");
            remove_owned(&docs[0].1);
        } else {
            assert_eq!(error.message(), "RUNTIME_NETWORK_EFFECT_QUARANTINED");
            assert_eq!(docs[0].1["document"]["phase"], "CreateIntent");
            assert_eq!(docs[0].1["document"]["observation"], Value::Null);
            let n = docs[0].1["document"]["topology"]["instance"]
                .as_str()
                .unwrap();
            let out = Command::new("/apex-engine-tools/docker")
                .arg("--host=unix:///run/apex-docker.sock")
                .args(["network", "ls", "--quiet", "--no-trunc"])
                .arg(format!("--filter=name=^apex-net-{n}$"))
                .output()
                .unwrap();
            assert!(out.status.success() && out.stdout.iter().all(u8::is_ascii_whitespace));
        }
        eprintln!("TASK4P simulated {point:?} root={}", root.display());
        f.stop().await;
    }
}
