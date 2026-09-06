//! Deterministic post-notification/pre-publication schedule, using real protected
//! deployment loading, the production bind phase, and an already connected mTLS client.
use super::*;
use crate::config::{Directory, deployment::Deployment};
use std::{
    fs,
    future::Future,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::mpsc,
    task::{Context, Waker},
};

struct Root(PathBuf);
impl Root {
    fn new(f: &Fixture, listen: std::net::SocketAddr) -> Self {
        let path =
            PathBuf::from("/root").join(format!("apex-task2-review-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Self(path);
        let (policy, catalog) = documents(&f.pki);
        root.write("peer-policy.json", &policy);
        root.write("launch-catalog.json", &catalog);
        root.write(
            "agent.json",
            &serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"listen":listen.to_string(),"installation_id":INSTALL,
                "agent_identity_id":"client-agent","enrollment_version":"enrollment-1",
                "host_policy_version":"host-1","authority_endpoint":f.authority_endpoint,
                "authority_tls_server_name":"control-plane-api"
            }))
            .unwrap(),
        );
        for (name, source) in [
            ("server-ca.pem", "ca.pem"),
            ("server-cert.pem", "control-plane-server.pem"),
            ("server-key.pem", "control-plane-server.key"),
            ("authority-ca.pem", "ca.pem"),
            ("authority-client-cert.pem", "agent-workload-client.pem"),
            ("authority-client-key.pem", "agent-workload-client.key"),
        ] {
            root.write(name, &f.pki.read("trusted-host", source));
        }
        root
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.0.join(name), bytes).unwrap();
        fs::set_permissions(self.0.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct HeldReader {
    reader: owner::Reader,
    release: Option<mpsc::Sender<()>>,
}
impl HeldReader {
    fn start(root: &Root) -> (Self, tokio::sync::oneshot::Receiver<Deployment>) {
        let path = root.0.clone();
        let (sent, loaded) = tokio::sync::oneshot::channel();
        let mut sent = Some(sent);
        let (release, held) = mpsc::channel();
        let reader = owner::Reader::start(move || {
            let (deployment, metadata) = Deployment::load(&Directory::open(&path)?, None)?;
            if let Some(sent) = sent.take() {
                let _ = sent.send(deployment); // Same early notification as production.
                let _ = held.recv(); // Cannot publish Metadata until explicitly released.
            }
            Ok(metadata)
        })
        .unwrap();
        (
            Self {
                reader,
                release: Some(release),
            },
            loaded,
        )
    }
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
impl Drop for HeldReader {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test]
async fn bootstrap_waits_for_reader_publication_before_binding_then_serves() {
    let f = Fixture::start().await;
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = socket.local_addr().unwrap();
    drop(socket);
    let root = Root::new(&f, listen);
    let (mut held, loaded) = HeldReader::start(&root);
    let deployment = tokio::time::timeout(BUDGET, loaded).await.unwrap().unwrap();
    let authority = RuntimeAuthorityClient::connect(deployment.authority_config())
        .await
        .unwrap();
    let shared = Arc::clone(&held.reader.shared);
    assert!(shared.lock().unwrap().metadata.is_none());
    let (shutdown, stopped) = watch::channel(false);
    let mut prepare = Box::pin(super::super::startup::prepare_listener(
        deployment,
        authority,
        shared,
        stopped.clone(),
        held.reader.publication.clone(),
    ));
    // Both the loader notification and real authority connect have completed.
    // One poll deterministically reaches the broken snapshot gate: no sleep,
    // timeout-as-proof, timing loop, or fake certificate extensions.
    assert!(
        prepare
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "bootstrap refused before the held reader could publish metadata"
    );
    let unbound = std::net::TcpListener::bind(listen).expect("must not bind before publication");
    drop(unbound);
    held.release();
    let (router, incoming) = tokio::time::timeout(BUDGET, prepare)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.local_addr().unwrap(), listen);
    let mut stopped = stopped;
    let serving = tokio::spawn(router.serve_with_incoming_shutdown(incoming, async move {
        let _ = stopped.changed().await;
    }));
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
        .identity(f.pki.identity("trusted-host", CONTROLLER));
    let channel = Endpoint::from_shared(format!("https://{listen}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = RuntimeExecutionServiceClient::new(channel);
    assert_eq!(
        client
            .reconcile_runtime(request())
            .await
            .unwrap_err()
            .message(),
        NOT_SERVING
    );
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 1);
    drop(client);
    shutdown.send(true).unwrap();
    tokio::time::timeout(BUDGET, serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(held); // Physical reader completion remains owned before root removal.
    drop(root);
    f.stop().await;
}

#[tokio::test]
async fn bootstrap_shutdown_cancels_publication_wait_but_keeps_reader_owned() {
    let f = Fixture::start().await;
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = socket.local_addr().unwrap();
    drop(socket);
    let root = Root::new(&f, listen);
    let (mut held, loaded) = HeldReader::start(&root);
    let deployment = tokio::time::timeout(BUDGET, loaded).await.unwrap().unwrap();
    let shared = Arc::clone(&held.reader.shared);
    let (sent, loaded) = tokio::sync::oneshot::channel();
    assert!(sent.send(Ok(deployment)).is_ok());
    let (shutdown, stopped) = watch::channel(false);
    let mut session = Box::pin(super::super::startup::session(
        loaded,
        Arc::clone(&shared),
        stopped,
        held.reader.publication.clone(),
    ));
    assert!(
        session
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    shutdown.send(true).unwrap();
    assert!(tokio::time::timeout(BUDGET, session).await.unwrap().is_ok());
    assert!(!*held.reader.publication.borrow());
    assert!(
        !shared.lock().unwrap().stopped,
        "session does not detach or consume the process-owned reader"
    );
    assert!(shared.lock().unwrap().metadata.is_none());
    let unbound = std::net::TcpListener::bind(listen).expect("cancelled startup must not bind");
    drop(unbound);
    held.release();
    drop(held); // joins the physical reader before the root can be removed
    assert!(shared.lock().unwrap().stopped);
    drop(root);
    f.stop().await;
}
