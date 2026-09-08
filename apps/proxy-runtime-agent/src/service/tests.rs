use super::*;
use crate::proto::{
    runtime_deployment_service_server::{RuntimeDeploymentService, RuntimeDeploymentServiceServer},
    runtime_execution_service_client::RuntimeExecutionServiceClient,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tonic::transport::{
    Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig, server::TcpIncoming,
};
#[path = "../../tests/runtime_peer_pair/pki.rs"]
mod pki;
use pki::{AGENT, CONTROLLER, Pki};
mod current_callback;
#[cfg(target_os = "linux")]
mod dormant;
mod health_observation;
mod limits;
pub(crate) mod network_inspection;

const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
struct Callback {
    policy: apex_auth::RuntimePeerPolicy,
    reply: Mutex<proto::RuntimeDeploymentSnapshot>,
    targets: Mutex<std::collections::BTreeMap<String, proto::RuntimeDeploymentSnapshot>>,
    calls: AtomicUsize,
    pin: Mutex<Vec<u8>>,
    hold: std::sync::atomic::AtomicBool,
    entered: Semaphore,
    release: Semaphore,
}
#[tonic::async_trait]
impl RuntimeDeploymentService for Arc<Callback> {
    async fn resolve_runtime_deployment(
        &self,
        r: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeDeploymentSnapshot>, Status> {
        let b = r.get_ref();
        let t = b.target.as_ref().unwrap();
        self.policy
            .authorize_agent_observation(
                &r,
                b.observed_controller_certificate_sha256
                    .as_slice()
                    .try_into()
                    .unwrap(),
                INSTALL,
                &t.workspace_id,
                &t.namespace_id,
            )
            .map_err(|_| Status::permission_denied("pair"))?;
        assert!(r.metadata().get("authorization").is_none());
        *self.pin.lock().unwrap() = b.observed_controller_certificate_sha256.clone();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        if self.hold.load(Ordering::SeqCst) {
            self.release.acquire().await.unwrap().forget();
        }
        let reply = self
            .targets
            .lock()
            .unwrap()
            .get(&t.proxy_id)
            .cloned()
            .unwrap_or_else(|| self.reply.lock().unwrap().clone());
        Ok(Response::new(reply))
    }
}
fn request() -> proto::RuntimeReconcileRequest {
    proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
            revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            generation: 9_007_199_254_740_993,
            fencing_token: 9_007_199_254_740_995,
        }),
        operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
        command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
        config_hash: "a".repeat(64),
    }
}
fn reply() -> proto::RuntimeDeploymentSnapshot {
    let r = request();
    let mut c: proto::RuntimeConfiguration = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("APEX_RUNTIME_FIXTURE_PATH").expect("real runtime export required"),
        )
        .unwrap(),
    )
    .unwrap();
    let t = r.target.as_ref().unwrap();
    c.workspace_id = t.workspace_id.clone();
    c.namespace_id = t.namespace_id.clone();
    c.proxy_id = t.proxy_id.clone();
    c.revision_id = t.revision_id.clone();
    c.generation = t.generation;
    c.config_hash = r.config_hash.clone();
    c.runtime_manifest_hash = crate::runtime_manifest_hash(&c).unwrap();
    let a = proto::RuntimeAuthoritySnapshot {
        schema_version: 1,
        target: r.target,
        operation_id: r.operation_id,
        command_id: r.command_id,
        action: 1,
        installation_id: INSTALL.into(),
        agent_identity_id: "client-agent".into(),
        observed_controller_identity_id: "client-controller".into(),
        peer_policy_version: "client-policy".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
        desired_state: 1,
        observed_state: 1,
        config_hash: r.config_hash,
        checked_at_unix_us: 9_007_199_254_740_993,
        lease_expires_at_unix_us: 9_007_199_264_740_993,
    };
    proto::RuntimeDeploymentSnapshot {
        schema_version: 1,
        authority: Some(a),
        configuration: Some(c),
        deployment_bindings_version: "bindings-1".into(),
    }
}
fn documents(pki: &Pki) -> (Vec<u8>, Vec<u8>) {
    let (p, c) = crate::owner::tests::documents();
    let mut p: serde_json::Value = serde_json::from_slice(&p).unwrap();
    p["peers"][0]["certificateSha256"] = pki::hex(&pki.pin(CONTROLLER)).into();
    p["peers"][0]["identityId"] = "client-controller".into();
    let mut agent = p["peers"][0].clone();
    agent["certificateSha256"] = pki::hex(&pki.pin(AGENT)).into();
    agent["identityId"] = "client-agent".into();
    agent["role"] = "agent".into();
    p["peers"].as_array_mut().unwrap().push(agent);
    (serde_json::to_vec(&p).unwrap(), c)
}
struct Fixture {
    pki: Pki,
    callback: Arc<Callback>,
    shared: owner::Shared,
    endpoint: String,
    #[cfg(target_os = "linux")]
    authority_endpoint: String,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>,
}
impl Fixture {
    async fn start() -> Self {
        let pki = Pki::require();
        let (p, c) = documents(&pki);
        let callback = Arc::new(Callback {
            policy: apex_auth::RuntimePeerPolicy::parse_json(&p).unwrap(),
            reply: Mutex::new(reply()),
            targets: Mutex::new(Default::default()),
            calls: AtomicUsize::new(0),
            pin: Mutex::new(vec![]),
            hold: std::sync::atomic::AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        });
        let (shutdown, stopped) = watch::channel(false);
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        #[cfg(target_os = "linux")]
        let authority_endpoint = endpoint.clone();
        let mut stop = stopped.clone();
        let cb = Arc::clone(&callback);
        let tls = || {
            ServerTlsConfig::new()
                .identity(pki.identity("trusted-host", "control-plane-server"))
                .client_ca_root(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
                .client_auth_optional(false)
                .timeout(BUDGET)
        };
        let callback_router = Server::builder()
            .tls_config(tls())
            .unwrap()
            .add_service(RuntimeDeploymentServiceServer::new(Arc::clone(&cb)))
            .add_service(
                proto::runtime_authority_service_server::RuntimeAuthorityServiceServer::new(cb),
            );
        let task = tokio::spawn(callback_router.serve_with_incoming_shutdown(
            incoming,
            async move {
                let _ = stop.changed().await;
            },
        ));
        let authority = RuntimeAuthorityClient::connect(crate::authority::AuthorityClientConfig {
            endpoint,
            tls_server_name: "control-plane-api".into(),
            ca_pem: pki.read("trusted-host", "ca.pem"),
            client_certificate_pem: pki.read("trusted-host", &format!("{AGENT}.pem")),
            client_key_pem: pki.read("trusted-host", &format!("{AGENT}.key")),
            installation_id: INSTALL.into(),
            agent_identity_id: "client-agent".into(),
            enrollment_version: "enrollment-1".into(),
            host_policy_version: "host-1".into(),
        })
        .await
        .unwrap();
        let shared = Arc::new(Mutex::new(owner::State {
            metadata: Some(Arc::new(owner::Metadata::parse(&p, &c).unwrap())),
            read_started: Instant::now(),
            stopped: false,
        }));
        let ingress = Ingress {
            authority: Arc::new(authority),
            installation: INSTALL.into(),
            shared: Arc::clone(&shared),
            slots: Semaphore::new(8),
            shutdown: stopped.clone(),
            #[cfg(target_os = "linux")]
            execution: None,
        };
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = format!("https://{}", incoming.local_addr().unwrap());
        let mut stop = stopped;
        let task2 = tokio::spawn(
            router(ingress, tls())
                .unwrap()
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = stop.changed().await;
                }),
        );
        Self {
            pki,
            callback,
            shared,
            endpoint,
            shutdown,
            #[cfg(target_os = "linux")]
            authority_endpoint,
            tasks: vec![task, task2],
        }
    }
    async fn client(
        &self,
        leaf: Option<(&str, &str)>,
    ) -> RuntimeExecutionServiceClient<tonic::transport::Channel> {
        let mut tls = ClientTlsConfig::new()
            .domain_name("control-plane-api")
            .ca_certificate(Certificate::from_pem(
                self.pki.read("trusted-host", "ca.pem"),
            ));
        if let Some((tree, leaf)) = leaf {
            tls = tls.identity(self.pki.identity(tree, leaf));
        }
        RuntimeExecutionServiceClient::new(
            Endpoint::from_shared(self.endpoint.clone())
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect_timeout(BUDGET)
                .connect_lazy(),
        )
    }
    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.callback.release.add_permits(8);
        for t in self.tasks {
            tokio::time::timeout(BUDGET, t)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
mod bootstrap;

#[tokio::test]
async fn production_listener_resolves_original_tls_then_refuses_effect_handoff() {
    let f = Fixture::start().await;
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    let mut r = Request::new(request());
    r.metadata_mut()
        .insert("authorization", "canary".parse().unwrap());
    assert_eq!(
        c.reconcile_runtime(r).await.unwrap_err().message(),
        NOT_SERVING
    );
    assert_eq!(
        f.callback.calls.load(Ordering::SeqCst),
        1,
        "real authority callback must run before unavailable handoff"
    );
    assert_eq!(*f.callback.pin.lock().unwrap(), f.pki.pin(CONTROLLER));
    // Invalid catalog selection must fail preparation, even though transport and authority succeed.
    let (p, catalog) = documents(&f.pki);
    let mut value: serde_json::Value = serde_json::from_slice(&catalog).unwrap();
    value["profiles"][0]["host_policy_version"] = "wrong".into();
    f.shared.lock().unwrap().metadata = Some(Arc::new(
        owner::Metadata::parse(&p, &serde_json::to_vec(&value).unwrap()).unwrap(),
    ));
    assert_eq!(
        c.reconcile_runtime(request()).await.unwrap_err().message(),
        "RUNTIME_LAUNCH_REFUSED"
    );
    for desired in [2, 3] {
        f.callback
            .reply
            .lock()
            .unwrap()
            .authority
            .as_mut()
            .unwrap()
            .desired_state = desired;
        assert_eq!(
            c.reconcile_runtime(request()).await.unwrap_err().message(),
            NOT_SERVING
        );
    }
    drop(c);
    f.stop().await;
}

#[tokio::test]
async fn production_listener_rejects_missing_wrong_tls_role_scope_and_malformed_claims() {
    let f = Fixture::start().await;
    for leaf in [
        None,
        Some(("untrusted-host", CONTROLLER)),
        Some(("trusted-host", AGENT)),
        Some(("trusted-host", pki::OTHER)),
    ] {
        let mut c = f.client(leaf).await;
        let mut r = Request::new(request());
        r.metadata_mut()
            .insert("x-forwarded-client-cert", "forged".parse().unwrap());
        assert!(c.reconcile_runtime(r).await.is_err());
    }
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    let mut r = request();
    r.target.as_mut().unwrap().namespace_id = "other".into();
    assert_eq!(
        c.reconcile_runtime(r).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let mut r = request();
    r.schema_version = 0;
    assert_eq!(
        c.reconcile_runtime(r).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    drop(c);
    f.stop().await;
}

#[tokio::test]
async fn replacement_during_callback_and_snapshot_mismatch_never_prepare() {
    let f = Fixture::start().await;
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    f.callback
        .reply
        .lock()
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .enrollment_version = "wrong".into();
    assert_ne!(
        c.reconcile_runtime(request()).await.unwrap_err().message(),
        NOT_SERVING
    );
    *f.callback.reply.lock().unwrap() = reply();
    f.callback.hold.store(true, Ordering::SeqCst);
    let task = tokio::spawn(async move { c.reconcile_runtime(request()).await });
    f.callback.entered.acquire_many(2).await.unwrap().forget();
    f.shared.lock().unwrap().metadata = None;
    f.callback.release.add_permits(1);
    assert_eq!(
        task.await.unwrap().unwrap_err().message(),
        owner::UNAVAILABLE
    );
    f.stop().await;
}

#[tokio::test]
async fn forged_terminal_and_unknown_online_states_cannot_reach_preparation() {
    let f = Fixture::start().await;
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    for observed in [0, 3, 4, 5, 999] {
        f.callback
            .reply
            .lock()
            .unwrap()
            .authority
            .as_mut()
            .unwrap()
            .observed_state = observed;
        let refusal = c.reconcile_runtime(request()).await.unwrap_err();
        assert_eq!(
            refusal.message(),
            if matches!(observed, 0 | 999) {
                "RUNTIME_AUTHORITY_REFUSED"
            } else {
                "RUNTIME_OPERATION_NOT_CURRENT"
            }
        );
    }
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 5);
    drop(c);
    f.stop().await;
}

async fn assert_retryable_online_state_reaches_handoff(observed: proto::ProxyObservedState) {
    let f = Fixture::start().await;
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    f.callback
        .reply
        .lock()
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .observed_state = observed.into();
    let refusal = c.reconcile_runtime(request()).await.unwrap_err();
    assert_eq!(refusal.message(), NOT_SERVING);
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*f.callback.pin.lock().unwrap(), f.pki.pin(CONTROLLER));
    drop(c);
    f.stop().await;
}

#[tokio::test]
async fn retryable_failed_reaches_handoff_through_real_tls_authority() {
    assert_retryable_online_state_reaches_handoff(proto::ProxyObservedState::Failed).await;
}

#[tokio::test]
async fn retryable_not_serving_reaches_handoff_through_real_tls_authority() {
    assert_retryable_online_state_reaches_handoff(proto::ProxyObservedState::NotServing).await;
}

#[tokio::test]
async fn stale_revoked_expired_policy_and_oversized_wire_dispatch_no_callback() {
    let f = Fixture::start().await;
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    let (p, catalog) = documents(&f.pki);
    let mut revoked: serde_json::Value = serde_json::from_slice(&p).unwrap();
    revoked["peers"][0]["revoked"] = true.into();
    f.shared.lock().unwrap().metadata = Some(Arc::new(
        owner::Metadata::parse(&serde_json::to_vec(&revoked).unwrap(), &catalog).unwrap(),
    ));
    assert_eq!(
        c.reconcile_runtime(request()).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    f.shared.lock().unwrap().metadata =
        Some(Arc::new(owner::Metadata::parse(&p, &catalog).unwrap()));
    f.shared.lock().unwrap().read_started = Instant::now() - owner::FRESHNESS;
    assert_eq!(
        c.reconcile_runtime(request()).await.unwrap_err().message(),
        owner::UNAVAILABLE
    );
    let mut expired: serde_json::Value = serde_json::from_slice(&p).unwrap();
    expired["expiresAtUnixUs"] = "100".into();
    assert!(owner::Metadata::parse(&serde_json::to_vec(&expired).unwrap(), &catalog).is_err());
    f.shared.lock().unwrap().metadata = None;
    assert_eq!(
        c.reconcile_runtime(request()).await.unwrap_err().message(),
        owner::UNAVAILABLE
    );
    let mut r = request();
    r.config_hash = "canary".repeat(1024);
    assert!(c.reconcile_runtime(r).await.is_err());
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    let mut plaintext = RuntimeExecutionServiceClient::new(
        Endpoint::from_shared(f.endpoint.replace("https:", "http:"))
            .unwrap()
            .connect_lazy(),
    );
    assert!(
        tokio::time::timeout(BUDGET, plaintext.reconcile_runtime(request()))
            .await
            .unwrap()
            .is_err()
    );
    drop(c);
    drop(plaintext);
    f.stop().await;
}

#[tokio::test]
async fn eight_global_slots_reject_overload_cancel_and_shutdown_without_effects() {
    let f = Fixture::start().await;
    f.callback.hold.store(true, Ordering::SeqCst);
    let mut tasks = vec![];
    for _ in 0..8 {
        let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
        tasks.push(tokio::spawn(
            async move { c.reconcile_runtime(request()).await },
        ));
    }
    tokio::time::timeout(BUDGET, f.callback.entered.acquire_many(8))
        .await
        .unwrap()
        .unwrap()
        .forget();
    let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
    assert_eq!(
        c.reconcile_runtime(request()).await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 8);
    tasks.pop().unwrap().abort();
    // A cancelled HTTP/2 stream must release its handler's borrowed permit.
    let deadline = Instant::now() + Duration::from_secs(1);
    let replacement = loop {
        let mut c = f.client(Some(("trusted-host", CONTROLLER))).await;
        let candidate = tokio::spawn(async move { c.reconcile_runtime(request()).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        if f.callback.calls.load(Ordering::SeqCst) == 9 {
            break candidate;
        }
        assert_eq!(
            candidate.await.unwrap().unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        assert!(
            Instant::now() < deadline,
            "cancelled call retained ingress capacity"
        );
    };
    f.shutdown.send(true).unwrap();
    for t in tasks {
        assert_eq!(
            t.await.unwrap().unwrap_err().message(),
            "RUNTIME_SHUTTING_DOWN"
        );
    }
    assert_eq!(
        replacement.await.unwrap().unwrap_err().message(),
        "RUNTIME_SHUTTING_DOWN"
    );
    drop(c);
    f.stop().await;
}
