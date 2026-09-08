//! Joined real Controller TLS -> registered route -> owned physical worker -> Docker.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
mod health;
type Reload = Box<dyn FnMut() -> Result<owner::Metadata, &'static str> + Send>;

struct StopOnDrop(watch::Sender<bool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

pub(crate) async fn check(
    root: &Path,
    metadata: owner::Metadata,
    binding: proto::ManagedDeploymentBinding,
    hashes: &(String, String),
) {
    check_inner(root, metadata, binding, hashes, None, None).await;
}

pub(crate) async fn check_health(
    root: &Path,
    metadata: owner::Metadata,
    binding: proto::ManagedDeploymentBinding,
    hashes: &(String, String),
    launch: &proto::RuntimeLaunchContext,
    reload: Reload,
) {
    check_inner(root, metadata, binding, hashes, Some(launch), Some(reload)).await;
}

async fn check_inner(
    root: &Path,
    mut metadata: owner::Metadata,
    binding: proto::ManagedDeploymentBinding,
    hashes: &(String, String),
    health_launch: Option<&proto::RuntimeLaunchContext>,
    reload: Option<Reload>,
) {
    let f = Fixture::start().await;
    // Panic unwinding must release physical cleanup before the outer runtime joins.
    let _stop_on_drop = StopOnDrop(f.shutdown.clone());
    let (policy, _) = documents(&f.pki);
    let mut policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    let target = binding.target.as_ref().unwrap();
    for peer in policy["peers"].as_array_mut().unwrap() {
        peer["grants"] = serde_json::json!([{"installationId":binding.installation_id,
            "workspaceId":target.workspace_id,"namespaceId":target.namespace_id}]);
    }
    let policy = serde_json::to_vec(&policy).unwrap();
    let (shared, _reader) = if let Some(mut reload) = reload {
        let mut reader = owner::Reader::start(move || {
            let mut metadata = reload()?;
            metadata.policy = apex_auth::RuntimePeerPolicy::parse_json(&policy)
                .map_err(|_| owner::UNAVAILABLE)?;
            Ok(metadata)
        })
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), reader.publication.wait_for(|v| *v))
            .await
            .unwrap()
            .unwrap();
        (Arc::clone(&reader.shared), Some(reader))
    } else {
        metadata.policy = apex_auth::RuntimePeerPolicy::parse_json(&policy).unwrap();
        (
            Arc::new(Mutex::new(owner::State {
                metadata: Some(Arc::new(metadata)),
                read_started: Instant::now(),
                stopped: false,
            })),
            None,
        )
    };
    let cache = root.join("inspection-cosign");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let config: crate::config::ExecutionConfig = serde_json::from_value(serde_json::json!({
        "journal_root":root.join("journal"),"staging_root":root.join("staging"),"material_root":root.join("material"),
        "docker_executable":"/apex-engine-tools/docker","docker_socket":"/run/apex-docker.sock","docker_config_root":root.join("docker-config"),
        "cosign_executable":"/apex-signature-tools/cosign","cosign_cache_root":cache,"network_profile":"isolated-bridge-v1"
    })).unwrap();
    let resources = crate::execution::Resources::open(&config, INSTALL).unwrap();
    let authority = Arc::new(
        RuntimeAuthorityClient::connect(crate::authority::AuthorityClientConfig {
            endpoint: f.authority_endpoint.clone(),
            tls_server_name: "control-plane-api".into(),
            ca_pem: f.pki.read("trusted-host", "ca.pem"),
            client_certificate_pem: f.pki.read("trusted-host", &format!("{AGENT}.pem")),
            client_key_pem: f.pki.read("trusted-host", &format!("{AGENT}.key")),
            installation_id: INSTALL.into(),
            agent_identity_id: "client-agent".into(),
            enrollment_version: "enrollment-1".into(),
            host_policy_version: "host-v1".into(),
        })
        .await
        .unwrap(),
    );
    let facility = crate::execution::Facility::start(
        resources,
        Arc::clone(&authority),
        Arc::clone(&shared),
        INSTALL.into(),
        f.shutdown.subscribe(),
    )
    .unwrap();
    let ingress = Ingress {
        authority,
        installation: INSTALL.into(),
        shared: Arc::clone(&shared),
        slots: Semaphore::new(8),
        shutdown: f.shutdown.subscribe(),
        execution: Some(facility),
    };
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let endpoint = format!("https://{}", incoming.local_addr().unwrap());
    let tls = ServerTlsConfig::new()
        .identity(f.pki.identity("trusted-host", "control-plane-server"))
        .client_ca_root(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
        .client_auth_optional(false);
    let mut stop = f.shutdown.subscribe();
    let server = tokio::spawn(router(ingress, tls).unwrap().serve_with_incoming_shutdown(
        incoming,
        async move {
            let _ = stop.changed().await;
        },
    ));
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
        .identity(f.pki.identity("trusted-host", CONTROLLER));
    let channel = Endpoint::from_shared(endpoint)
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut c = RuntimeNetworkInspectionClient::new(channel.clone());
    let request = proto::RuntimeNetworkInspectionRequest {
        schema_version: 1,
        binding: Some(binding),
        nonce: vec![19; 32],
    };
    for _ in 0..2 {
        if health_launch.is_none() {
            shared.lock().unwrap().read_started = Instant::now();
        }
        let started = Instant::now();
        let response = c
            .check(request.clone())
            .await
            .expect("real TLS and owned physical inspection must join")
            .into_inner();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(response.schema_version, 1);
        assert_eq!(response.binding, request.binding);
        assert_eq!(response.nonce, request.nonce);
        assert!(response.confined);
        assert_eq!(response.valid_for_us, 10_000_000);
        assert_eq!(
            (
                &response.gateway_process_sha256,
                &response.guard_process_sha256
            ),
            (&hashes.0, &hashes.1)
        );
        assert!(crate::shapes::hex_hash(&response.network_binding_sha256));
        eprintln!(
            "NETWORK INSPECTION real TLS owned-worker positive elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
    if let Some(launch) = health_launch {
        health::check(channel, &shared, request.binding.as_ref().unwrap(), launch).await;
    }
    shared.lock().unwrap().metadata = None;
    assert_eq!(
        c.check(request).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        f.callback.calls.load(Ordering::SeqCst),
        0,
        "read-only inspection cannot call operation authority"
    );
    drop(c);
    f.stop().await;
    server.await.unwrap().unwrap();
}
