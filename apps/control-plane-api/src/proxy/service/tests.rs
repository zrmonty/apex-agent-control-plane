use std::sync::Arc;

use crate::{
    CreateProxy, ExactScope, InMemoryProxyStore, OperatorCaller, OperatorTokenAuthenticator,
    ProxyId, ProxyLifecycleStore, ProxyRevisionId, ProxyRevisionStore, ProxyStore, PublishRevision,
    StaticOperatorTokenResolver, TransitionProxyLifecycle, UpdateProxyDraft, proto,
};
use tonic::{Code, Request};

use super::super::{
    LifecycleCommand, McpProxyService, ProxyEventSink, ProxyLifecycleEvent, ProxyRuntimeProvider,
};

struct TestRuntime;

impl ProxyRuntimeProvider for TestRuntime {
    fn reconcile(&self, _revision: &crate::McpProxyRevision) -> Result<(), crate::ProxyError> {
        Ok(())
    }
    fn discover(
        &self,
        revision: &crate::McpProxyRevision,
        upstream_id: &str,
    ) -> Result<proto::ProxyUpstreamDiscovery, crate::ProxyError> {
        let upstream = revision
            .spec
            .upstreams
            .iter()
            .find(|value| value.upstream_id == upstream_id)
            .ok_or_else(crate::ProxyError::revision_not_found)?;
        Ok(proto::ProxyUpstreamDiscovery {
            upstream_id: upstream.upstream_id.clone(),
            server_identity: upstream.server_identity.clone(),
            discovered_tools: vec![],
            discovered_resources: vec![],
            discovered_prompts: vec![],
            schema_hash: upstream.tool_catalog_hash.clone().unwrap_or_default(),
            redaction_status: proto::McpProxyRedactionStatus::Redacted as i32,
        })
    }
    fn test_connection(
        &self,
        revision: &crate::McpProxyRevision,
        upstream_id: &str,
    ) -> Result<proto::ProxyConnectionTest, crate::ProxyError> {
        let upstream = revision
            .spec
            .upstreams
            .iter()
            .find(|value| value.upstream_id == upstream_id)
            .ok_or_else(crate::ProxyError::revision_not_found)?;
        Ok(proto::ProxyConnectionTest {
            connected: true,
            upstream_id: upstream.upstream_id.clone(),
            server_identity: upstream.server_identity.clone(),
            summary: "test provider".to_owned(),
            redaction_status: proto::McpProxyRedactionStatus::Redacted as i32,
        })
    }
}

struct TestEvents;

impl ProxyEventSink for TestEvents {
    fn emit(&self, _event: ProxyLifecycleEvent) -> Result<(), crate::ProxyError> {
        Ok(())
    }
}

const WORKSPACE: &str = "workspace-a";
const NAMESPACE: &str = "namespace-a";
const PROXY: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";

#[tokio::test]
async fn create_proxy_denies_an_authenticated_operator_outside_the_exact_scope() {
    let service = service(Arc::new(InMemoryProxyStore::default()));
    let mut request = Request::new(proto::CreateProxyRequest {
        request_id: id(160),
        workspace_id: "workspace-b".into(),
        namespace_id: "namespace-b".into(),
        proxy_id: id(161),
        display_name: "Denied proxy".into(),
        slug: "denied-proxy".into(),
        description: None,
        owner: None,
        tags: vec![],
    });
    authorize(&mut request);
    assert_eq!(
        service.create_proxy(request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[test]
fn deploy_is_idempotent_pause_resume_and_retirement_are_terminal() {
    let store = Arc::new(InMemoryProxyStore::default());
    let revision = published(&store);
    transition(&store, 10, &revision, LifecycleCommand::Validate, false);
    transition(
        &store,
        11,
        &revision,
        LifecycleCommand::ValidationSucceeded,
        false,
    );
    let deployed = transition(&store, 12, &revision, LifecycleCommand::Deploy, true);
    let duplicate = transition(&store, 12, &revision, LifecycleCommand::Deploy, true);
    assert_eq!(deployed, duplicate);
    transition(&store, 13, &revision, LifecycleCommand::Ready, false);
    assert_eq!(
        transition(&store, 14, &revision, LifecycleCommand::Pause, false).lifecycle_state,
        crate::ProxyLifecycleState::Paused
    );
    assert_eq!(
        transition(&store, 15, &revision, LifecycleCommand::Resume, false).lifecycle_state,
        crate::ProxyLifecycleState::Provisioning
    );
    transition(&store, 16, &revision, LifecycleCommand::Ready, false);
    assert_eq!(
        store
            .get_revision(scope(), proxy(), revision.clone())
            .unwrap()
            .lifecycle_state,
        crate::ProxyLifecycleState::Ready
    );
    transition(&store, 17, &revision, LifecycleCommand::Retire, false);
    assert_eq!(
        transition(&store, 18, &revision, LifecycleCommand::Retired, false).lifecycle_state,
        crate::ProxyLifecycleState::Retired
    );
    assert!(
        store
            .transition(mutation(19, &revision, LifecycleCommand::Pause, false))
            .is_err()
    );
}

#[test]
fn deploy_refuses_missing_approval() {
    let store = Arc::new(InMemoryProxyStore::default());
    let revision = published(&store);
    transition(&store, 20, &revision, LifecycleCommand::Validate, false);
    transition(
        &store,
        21,
        &revision,
        LifecycleCommand::ValidationSucceeded,
        false,
    );
    assert_eq!(
        store
            .transition(mutation(22, &revision, LifecycleCommand::Deploy, false))
            .unwrap_err()
            .code(),
        "PROXY_APPROVAL_REQUIRED"
    );
}

#[tokio::test]
async fn rollback_accepts_the_active_ready_immutable_revision() {
    let store = Arc::new(InMemoryProxyStore::default());
    let revision = published(&store);
    transition(&store, 30, &revision, LifecycleCommand::Validate, false);
    transition(
        &store,
        31,
        &revision,
        LifecycleCommand::ValidationSucceeded,
        false,
    );
    transition(&store, 32, &revision, LifecycleCommand::Deploy, true);
    transition(&store, 33, &revision, LifecycleCommand::Ready, false);
    let service = service(Arc::clone(&store));
    let mut request = Request::new(proto::RollbackProxyRequest {
        request_id: id(34),
        workspace_id: WORKSPACE.into(),
        namespace_id: NAMESPACE.into(),
        proxy_id: PROXY.into(),
        revision_id: revision.to_string(),
        target_revision_id: revision.to_string(),
        expected_revision_id: Some(revision.to_string()),
        reason_code: Some("proxy.rollback".into()),
    });
    authorize(&mut request);
    let response = service
        .rollback_proxy(request)
        .await
        .unwrap()
        .into_inner()
        .proxy
        .unwrap();
    assert_eq!(response.active_revision_id, revision.to_string());
    assert_eq!(
        response.lifecycle_state,
        proto::McpProxyLifecycleState::Ready as i32
    );
}

fn service(store: Arc<InMemoryProxyStore>) -> McpProxyService<StaticOperatorTokenResolver> {
    McpProxyService::from_store(
        OperatorTokenAuthenticator::new(StaticOperatorTokenResolver::new().with_token(
            "operator-token-with-sufficient-length",
            OperatorCaller::scoped("operator:alice", ["workspace-a/namespace-a"]).unwrap(),
        )),
        store,
    )
    .with_runtime_provider(Arc::new(TestRuntime))
    .with_event_sink(Arc::new(TestEvents))
}
fn authorize<T>(request: &mut Request<T>) {
    request.metadata_mut().insert(
        "authorization",
        "Bearer operator-token-with-sufficient-length"
            .parse()
            .unwrap(),
    );
}
fn scope() -> ExactScope {
    ExactScope {
        workspace_id: WORKSPACE.into(),
        namespace_id: NAMESPACE.into(),
    }
}
fn proxy() -> ProxyId {
    ProxyId::new(PROXY).unwrap()
}
fn id(n: u8) -> String {
    format!("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e{n:02x}")
}
fn published(store: &Arc<InMemoryProxyStore>) -> ProxyRevisionId {
    store
        .create(CreateProxy {
            request_id: id(1),
            scope: scope(),
            proxy_id: proxy(),
            display_name: "Proxy".into(),
            slug: "proxy".into(),
            description: None,
            owner: None,
        })
        .unwrap();
    let draft = store
        .update_draft(UpdateProxyDraft {
            request_id: id(2),
            scope: scope(),
            proxy_id: proxy(),
            expected_revision_id: None,
            actor_id: "operator:alice".into(),
            spec: super::super::tests::valid_proxy_spec(),
        })
        .unwrap()
        .draft_revision_id
        .unwrap();
    store
        .publish_revision(PublishRevision {
            request_id: id(3),
            scope: scope(),
            proxy_id: proxy(),
            draft_revision_id: draft,
            expected_revision_id: None,
            actor_id: "operator:alice".into(),
        })
        .unwrap()
        .revision_id
}
fn mutation(
    n: u8,
    revision: &ProxyRevisionId,
    command: LifecycleCommand,
    approved: bool,
) -> TransitionProxyLifecycle {
    TransitionProxyLifecycle {
        request_id: id(n),
        scope: scope(),
        proxy_id: proxy(),
        revision_id: revision.clone(),
        expected_revision_id: Some(revision.clone()),
        actor_id: "operator:alice".into(),
        reason_code: "proxy.lifecycle".into(),
        command,
        approved,
    }
}
fn transition(
    store: &Arc<InMemoryProxyStore>,
    n: u8,
    revision: &ProxyRevisionId,
    command: LifecycleCommand,
    approved: bool,
) -> crate::McpProxy {
    store
        .transition(mutation(n, revision, command, approved))
        .unwrap()
}
