use super::{
    fixture::*,
    pki,
    process::{self, Process},
};
use apex_control_plane_api::proto::{
    self, mcp_proxy_service_client::McpProxyServiceClient,
    runtime_execution_service_client::RuntimeExecutionServiceClient,
};
use prost::Message;
use std::{
    process::Command,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[test]
#[ignore = "requires explicit owned Linux Docker/Cosign/PostgreSQL fixtures; run with --ignored"]
fn actual_joint_durable_dormant_restart_pause_retire_isolation() {
    let f = Fixture::new();
    eprintln!("joint evidence root: {}", f.root.display());
    protected_configuration(&f);
    let mut cp = Process::control(&f);
    let mut agent = Process::agent(&f);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let operations = runtime.block_on(async {
        let mut client =
            McpProxyServiceClient::new(process::channel(&f, f.cp, pki::CONTROLLER).await);
        let mut operations = vec![];
        for (index, p) in f.proxies.iter().enumerate() {
            let proxy = client
                .get_proxy(process::operator(proto::GetProxyRequest {
                    workspace_id: p.scope.workspace_id.clone(),
                    namespace_id: p.scope.namespace_id.clone(),
                    proxy_id: p.id.to_string(),
                }))
                .await
                .unwrap()
                .into_inner()
                .proxy
                .unwrap();
            client
                .validate_proxy(process::operator(proto::ValidateProxyRequest {
                    request_id: Uuid::now_v7().to_string(),
                    workspace_id: p.scope.workspace_id.clone(),
                    namespace_id: p.scope.namespace_id.clone(),
                    proxy_id: p.id.to_string(),
                    expected_revision_id: Some(p.revision.revision_id.to_string()),
                    draft: proxy.spec,
                }))
                .await
                .expect("real durable validation");
            let request = proto::DeployProxyRequest {
                request_id: Uuid::now_v7().to_string(),
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
                revision_id: p.revision.revision_id.to_string(),
                expected_revision_id: Some(p.revision.revision_id.to_string()),
            };
            let response = client
                .deploy_proxy(process::operator(request.clone()))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response,
                client
                    .deploy_proxy(process::operator(request))
                    .await
                    .unwrap()
                    .into_inner()
            );
            assert_eq!(
                response.proxy.unwrap().lifecycle_state,
                proto::McpProxyLifecycleState::Provisioning as i32
            );
            let op = response.operation.unwrap();
            assert_eq!(op.generation, 1);
            assert_eq!(op.observed_state, proto::ProxyObservedState::Pending as i32);
            let query = proto::GetProxyOperationRequest {
                scope: Some(f.target(index)),
                operation_id: op.operation_id.clone(),
            };
            let current = client
                .get_proxy_operation(process::operator(query.clone()))
                .await
                .unwrap()
                .into_inner()
                .operation
                .unwrap();
            assert_eq!(current.operation_id, op.operation_id);
            let mut foreign = query;
            foreign.scope.as_mut().unwrap().namespace_id = if index == 0 {
                "namespace-two"
            } else {
                "namespace"
            }
            .into();
            assert_eq!(
                client
                    .get_proxy_operation(process::operator(foreign))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
            operations.push(op);
        }
        operations
    });
    let first = wait_dormant(&f, 0, &operations[0], 0);
    let second = wait_dormant(&f, 1, &operations[1], 0);
    // The actual agent producer preserves the reversed protected catalog order.
    // CP must accept it without rewriting the original launch or its hash.
    for response in [&first, &second] {
        let launch = response
            .runtime
            .as_ref()
            .unwrap()
            .launch_attestation
            .as_ref()
            .unwrap()
            .launch
            .as_ref()
            .unwrap();
        assert_eq!(
            launch.materials.iter().map(|m| m.role).collect::<Vec<_>>(),
            (1..=13).rev().collect::<Vec<_>>()
        );
        assert_eq!(
            launch.health.as_ref().unwrap().credential_ref,
            launch.materials[12].reference
        );
    }
    dormant(&first.runtime.as_ref().unwrap().runtime_id);
    dormant(&second.runtime.as_ref().unwrap().runtime_id);
    let request_bytes: Vec<u8> = f
        .database
        .client()
        .query_one(
            "SELECT request_bytes FROM mcp_proxy_runtime_attempts WHERE proxy_id=$1",
            &[f.proxies[0].id.as_uuid()],
        )
        .unwrap()
        .get(0);
    runtime.block_on(refusals(
        &f,
        proto::RuntimeReconcileRequest::decode(request_bytes.as_slice()).unwrap(),
    ));
    cp.stop();
    agent.stop();
    f.expire(0);
    f.expire(1);
    cp = Process::control(&f);
    agent = Process::agent(&f);
    let recovered = wait_dormant(
        &f,
        0,
        &operations[0],
        first
            .claims
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .fencing_token,
    );
    assert_eq!(
        recovered.runtime.as_ref().unwrap().target,
        first.runtime.as_ref().unwrap().target
    );
    assert_eq!(
        recovered.runtime.as_ref().unwrap().runtime_id,
        first.runtime.as_ref().unwrap().runtime_id
    );
    assert_eq!(
        recovered.runtime.as_ref().unwrap().launch_attestation,
        first.runtime.as_ref().unwrap().launch_attestation
    );
    runtime.block_on(async {
        let mut client =
            McpProxyServiceClient::new(process::channel(&f, f.cp, pki::CONTROLLER).await);
        let p = &f.proxies[0];
        let paused = client
            .pause_proxy(process::operator(proto::PauseProxyRequest {
                request_id: Uuid::now_v7().to_string(),
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
                revision_id: p.revision.revision_id.to_string(),
                expected_revision_id: Some(p.revision.revision_id.to_string()),
                reason_code: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .operation
            .unwrap();
        assert_eq!(
            paused.observed_state,
            proto::ProxyObservedState::Pending as i32
        );
        // Synchronous PostgreSQL polling is on the test owner, never CP Tokio workers.
        tokio::task::block_in_place(|| wait_state(&f, &paused, proto::ProxyObservedState::Paused));
        dormant(&second.runtime.as_ref().unwrap().runtime_id);
        for (index, p) in f.proxies.iter().enumerate() {
            let request = proto::RetireProxyRequest {
                request_id: Uuid::now_v7().to_string(),
                workspace_id: p.scope.workspace_id.clone(),
                namespace_id: p.scope.namespace_id.clone(),
                proxy_id: p.id.to_string(),
                revision_id: p.revision.revision_id.to_string(),
                expected_revision_id: Some(p.revision.revision_id.to_string()),
                reason_code: None,
            };
            let retired = process::management(|| {
                let (mut client, request) = (client.clone(), request.clone());
                async move { client.retire_proxy(process::operator(request)).await }
            })
            .await
            .unwrap()
            .into_inner()
            .operation
            .unwrap();
            assert_eq!(
                retired.observed_state,
                proto::ProxyObservedState::Pending as i32
            );
            tokio::task::block_in_place(|| {
                wait_state(&f, &retired, proto::ProxyObservedState::Retired)
            });
            let response = tokio::task::block_in_place(|| f.runtime_response(index));
            assert!(response.runtime.is_none());
            assert_eq!(
                response.observed_state,
                proto::ProxyObservedState::Retired as i32
            );
            let id = if index == 0 { &first } else { &second }
                .runtime
                .as_ref()
                .unwrap()
                .runtime_id
                .clone();
            assert!(!inspect(&id).status.success());
            if index == 0 {
                dormant(&second.runtime.as_ref().unwrap().runtime_id);
            }
        }
    });
    cp.stop();
    agent.stop();
}

pub(super) fn wait_dormant(
    f: &Fixture,
    index: usize,
    op: &proto::ProxyOperation,
    after_fence: u64,
) -> proto::RuntimeReconcileResponse {
    // Convergence may need a second 180s lease after uncertain transport. This
    // never extends any physical job/RPC budget or resets a durable fence.
    let end = Instant::now() + Duration::from_secs(390);
    loop {
        let state = f.observed(op);
        assert_ne!(
            state.observed_state,
            proto::ProxyObservedState::Ready as i32
        );
        let row=f.database.client().query_opt("SELECT response_bytes FROM mcp_proxy_runtime_attempts WHERE proxy_id=$1 AND response_bytes IS NOT NULL",&[f.proxies[index].id.as_uuid()]).unwrap();
        if let Some(row) = row {
            let response =
                proto::RuntimeReconcileResponse::decode(row.get::<_, Vec<u8>>(0).as_slice())
                    .unwrap();
            if let Some(installed) = &response.runtime
                && response
                    .claims
                    .as_ref()
                    .unwrap()
                    .target
                    .as_ref()
                    .unwrap()
                    .fencing_token
                    > after_fence
            {
                assert_eq!(
                    response.observed_state,
                    proto::ProxyObservedState::NotServing as i32
                );
                assert!(!installed.ready);
                return response;
            }
        }
        assert!(
            Instant::now() < end,
            "joint dormant outcome deadline, observed {}",
            state.observed_state
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn wait_state(f: &Fixture, op: &proto::ProxyOperation, wanted: proto::ProxyObservedState) {
    let end = Instant::now() + Duration::from_secs(390);
    loop {
        let actual = f.observed(op);
        if actual.observed_state == wanted as i32 {
            return;
        }
        assert_ne!(
            actual.observed_state,
            proto::ProxyObservedState::Ready as i32
        );
        assert!(
            Instant::now() < end,
            "cleanup deadline, observed {}",
            actual.observed_state
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
async fn refusals(f: &Fixture, request: proto::RuntimeReconcileRequest) {
    let mut wrong =
        RuntimeExecutionServiceClient::new(process::channel(f, f.agent, pki::AGENT).await);
    let denied = wrong.reconcile_runtime(request.clone()).await.unwrap_err();
    // The approved physical facility maps its local authority-client role
    // refusal to this static unavailable outcome (not the no-effects ingress).
    assert_eq!(denied.code(), tonic::Code::Unavailable);
    assert_eq!(denied.message(), "RUNTIME_AUTHORITY_REFUSED");
    let mut controller =
        RuntimeExecutionServiceClient::new(process::channel(f, f.agent, pki::CONTROLLER).await);
    let mut bad = request.clone();
    bad.config_hash = "f".repeat(64);
    let denied = controller.reconcile_runtime(bad).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unavailable);
    assert_eq!(denied.message(), "RUNTIME_AUTHORITY_REFUSED");
    let mut stale = request;
    stale.target.as_mut().unwrap().generation += 1;
    let denied = controller.reconcile_runtime(stale).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unavailable);
    assert_eq!(denied.message(), "RUNTIME_AUTHORITY_REFUSED");
}
fn protected_configuration(f: &Fixture) {
    use apex_control_plane_api::RuntimeExecutionConfig;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let base = f.root.join("control");
    let path = base.join("execution.json");
    RuntimeExecutionConfig::load(&base, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(RuntimeExecutionConfig::load(&base, &path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = base.join("execution-alias.json");
    symlink(&path, &alias).unwrap();
    assert!(RuntimeExecutionConfig::load(&base, &alias).is_err());
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, b"{}").unwrap();
    assert!(RuntimeExecutionConfig::load(&base, &path).is_err());
    fs::write(&path, bytes).unwrap();
    RuntimeExecutionConfig::load(&base, &path).unwrap();
}
fn inspect(id: &str) -> std::process::Output {
    assert!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    Command::new("/apex-engine-tools/docker")
        .args(["--host", "unix:///run/apex-docker.sock", "inspect", id])
        .output()
        .unwrap()
}
pub(super) fn dormant(id: &str) {
    let out = inspect(id);
    assert!(out.status.success());
    let values: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let value = &values[0];
    assert_eq!(value["State"]["Status"], "created");
    assert_eq!(value["State"]["Running"], false);
    assert_eq!(value["HostConfig"]["NetworkMode"], "none");
    assert!(
        value["HostConfig"]["PortBindings"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}
