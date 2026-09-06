//! Authenticated service retries against the actual disposable PostgreSQL store.
use super::support::Fixture;
use apex_control_plane_api::{
    McpProxyService, OperatorCaller, OperatorTokenAuthenticator, PostgresProxyStore,
    StaticOperatorTokenResolver, proto,
};
use std::sync::Arc;
use tonic::{Code, Request};
use uuid::Uuid;

#[path = "service_retry_view.rs"]
mod approval_view;

fn authenticator() -> OperatorTokenAuthenticator<StaticOperatorTokenResolver> {
    OperatorTokenAuthenticator::new(
        StaticOperatorTokenResolver::new()
            .with_token(
                "operator-token-with-sufficient-length",
                OperatorCaller::scoped("operator", ["workspace/namespace"]).unwrap(),
            )
            .with_token(
                "second-operator-token-sufficient-length",
                OperatorCaller::scoped("other-operator", ["workspace/namespace"]).unwrap(),
            ),
    )
}

fn service(store: Arc<PostgresProxyStore>) -> McpProxyService<StaticOperatorTokenResolver> {
    McpProxyService::from_store(authenticator(), Arc::clone(&store)).with_managed_store(store)
}

fn authorize<T>(input: T, other: bool) -> Request<T> {
    let mut request = Request::new(input);
    request.metadata_mut().insert(
        "authorization",
        if other {
            "Bearer second-operator-token-sufficient-length"
        } else {
            "Bearer operator-token-with-sufficient-length"
        }
        .parse()
        .unwrap(),
    );
    request
}

fn deploy(f: &Fixture) -> proto::DeployProxyRequest {
    proto::DeployProxyRequest {
        request_id: Uuid::now_v7().to_string(),
        workspace_id: f.input.scope.workspace_id.clone(),
        namespace_id: f.input.scope.namespace_id.clone(),
        proxy_id: f.input.proxy_id.to_string(),
        revision_id: f.revision.revision_id.to_string(),
        expected_revision_id: Some(f.revision.revision_id.to_string()),
    }
}

#[test]
fn service_retry_resolves_frozen_semantics_before_current_revision_lookup() {
    let f = Fixture::new(false);
    let store = Arc::new(PostgresProxyStore::connect(&f.database.url).unwrap());
    let service = service(store);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let original = deploy(&f);
    runtime.block_on(async {
        let accepted = service
            .deploy_proxy(authorize(original.clone(), false))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(accepted.operation.as_ref().unwrap().generation, 2);
        let duplicate = service
            .deploy_proxy(authorize(original.clone(), false))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(duplicate, accepted);
        // A valid but nonexistent changed revision must be an exact-request
        // conflict, not a fresh lookup's NotFound result.
        let mut changed = original.clone();
        changed.revision_id = Uuid::now_v7().to_string();
        let error = service
            .deploy_proxy(authorize(changed, false))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Aborted, "{error}");
        assert!(error.message().contains("PROXY_REVISION_CONFLICT"));
    });
}

#[test]
fn service_retry_recovers_committed_acceptance_when_approval_allows_then_errors() {
    use apex_control_plane_api::{ProxyApprovalAuthority, ProxyApprovalRequest, ProxyError};
    use std::sync::Mutex;
    #[derive(Default)]
    struct AllowsThenErrors(Mutex<Vec<ProxyApprovalRequest>>);
    impl ProxyApprovalAuthority for AllowsThenErrors {
        fn is_approved(&self, request: ProxyApprovalRequest) -> Result<bool, ProxyError> {
            let mut requests = self.0.lock().unwrap();
            requests.push(request);
            if requests.len() == 1 {
                Ok(true)
            } else {
                Err(ProxyError::new(
                    "PROXY_STORE_UNAVAILABLE",
                    "Approval unavailable.",
                ))
            }
        }
    }
    let f = Fixture::new(false);
    let store = Arc::new(PostgresProxyStore::connect(&f.database.url).unwrap());
    let authority = Arc::new(AllowsThenErrors::default());
    // The production publication gate deliberately allows only approval=None.
    // Exercise the configured service extension through a revision-read view;
    // all acceptance, conflict, evidence and recovery persistence is actual PG.
    // This does not claim production approval-required publication support.
    let service = McpProxyService::from_store(
        authenticator(),
        Arc::new(approval_view::ApprovalReadView(Arc::clone(&store))),
    )
    .with_managed_store(store)
    .with_approval_authority(authority.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let original = deploy(&f);
    let accepted = runtime
        .block_on(service.deploy_proxy(authorize(original.clone(), false)))
        .expect("first approval allows durable acceptance")
        .into_inner();
    assert_eq!(accepted.operation.as_ref().unwrap().generation, 2);
    let before = f.bytes();
    for _ in 0..2 {
        let retry = runtime
            .block_on(service.deploy_proxy(authorize(original.clone(), false)))
            .expect("committed acceptance must survive approval authority outage")
            .into_inner();
        assert_eq!(retry, accepted);
    }
    let queries = authority.0.lock().unwrap().clone();
    assert_eq!(
        queries.len(),
        1,
        "exact retries must not consult approval authority"
    );
    assert_eq!(
        queries[0],
        ProxyApprovalRequest {
            scope: f.input.scope.clone(),
            proxy_id: f.input.proxy_id.clone(),
            revision_id: f.revision.revision_id.clone(),
            actor_id: "operator".into(),
            action: "deploy".into(),
        }
    );
    // Frozen acceptance never authorizes different semantics, even during outage.
    for field in ["actor", "revision", "expected"] {
        let mut changed = original.clone();
        match field {
            "revision" => changed.revision_id = Uuid::now_v7().to_string(),
            "expected" => changed.expected_revision_id = None,
            _ => (),
        }
        let error = runtime
            .block_on(service.deploy_proxy(authorize(changed, field == "actor")))
            .unwrap_err();
        assert_eq!(error.code(), Code::Aborted, "{field}: {error}");
    }
    let changed_action = proto::PauseProxyRequest {
        request_id: original.request_id.clone(),
        workspace_id: original.workspace_id.clone(),
        namespace_id: original.namespace_id.clone(),
        proxy_id: original.proxy_id.clone(),
        revision_id: original.revision_id.clone(),
        expected_revision_id: original.expected_revision_id.clone(),
        reason_code: Some("proxy.deploy".into()),
    };
    assert_eq!(
        runtime
            .block_on(service.pause_proxy(authorize(changed_action, false)))
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let mut wrong_scope = original.clone();
    wrong_scope.namespace_id = "other-namespace".into();
    assert_eq!(
        runtime
            .block_on(service.deploy_proxy(authorize(wrong_scope, false)))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut new_request = original;
    new_request.request_id = Uuid::now_v7().to_string();
    assert_eq!(
        runtime
            .block_on(service.deploy_proxy(authorize(new_request, false)))
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        authority.0.lock().unwrap().len(),
        2,
        "new acceptance must consult authority"
    );
    assert_eq!(
        f.bytes(),
        before,
        "retries and refusals must not mutate durable rows"
    );
}
