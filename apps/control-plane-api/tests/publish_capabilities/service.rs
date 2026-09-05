use std::sync::{Arc, Mutex};

use apex_control_plane_api::{
    InMemoryProxyStore, McpProxyService, OperatorCaller, OperatorTokenAuthenticator, ProxyError,
    ProxyEventSink, ProxyLifecycleEvent, ProxyStore, StaticOperatorTokenResolver, proto,
};
use tonic::{Code, Request};

use super::fixtures::{cli_profile, create, edit, portfolio_spec, publish};

#[derive(Default)]
struct Events(Mutex<Vec<ProxyLifecycleEvent>>);

impl ProxyEventSink for Events {
    fn emit(&self, event: ProxyLifecycleEvent) -> Result<(), ProxyError> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

#[test]
fn rejected_publication_emits_no_success_event_and_repaired_publication_emits_once() {
    // Store and runtime ownership stays outside entered Tokio. No runtime provider
    // is supplied: this tests only service/store publication and event dispatch.
    let store = Arc::new(InMemoryProxyStore::default());
    let events = Arc::new(Events::default());
    let created = store.create(create()).unwrap();
    let mut unsupported = portfolio_spec();
    unsupported.cli_profiles.push(cli_profile());
    let draft = store.update_draft(edit(&created, unsupported)).unwrap();
    let attempt = publish(&draft);
    let service = McpProxyService::from_store(
        OperatorTokenAuthenticator::new(
            StaticOperatorTokenResolver::new().with_token(
                "publication-component-token-not-a-production-secret",
                OperatorCaller::scoped(
                    "operator:publisher",
                    ["publish-workspace/publish-namespace"],
                )
                .unwrap(),
            ),
        ),
        store.clone(),
    )
    .with_event_sink(events.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let request = |attempt: &apex_control_plane_api::PublishRevision| {
        let mut request = Request::new(proto::PublishProxyRevisionRequest {
            request_id: attempt.request_id.clone(),
            workspace_id: attempt.scope.workspace_id.clone(),
            namespace_id: attempt.scope.namespace_id.clone(),
            proxy_id: attempt.proxy_id.to_string(),
            draft_revision_id: attempt.draft_revision_id.to_string(),
            expected_revision_id: attempt
                .expected_revision_id
                .as_ref()
                .map(ToString::to_string),
        });
        request.metadata_mut().insert(
            "authorization",
            "Bearer publication-component-token-not-a-production-secret"
                .parse()
                .unwrap(),
        );
        request
    };
    let result = runtime.block_on(service.publish_proxy_revision(request(&attempt)));
    assert!(
        events.0.lock().unwrap().is_empty(),
        "refused publication emitted success"
    );
    assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(
        store
            .get(draft.scope.clone(), draft.proxy_id.clone())
            .unwrap(),
        draft
    );

    let repaired = store.update_draft(edit(&draft, portfolio_spec())).unwrap();
    let mut retry = publish(&repaired);
    retry.request_id = attempt.request_id;
    let response = runtime
        .block_on(service.publish_proxy_revision(request(&retry)))
        .unwrap();
    let revision = response.into_inner().revision.unwrap();
    let observed = events.0.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].request_id, retry.request_id);
    assert_eq!(observed[0].operation, "publish_proxy_revision");
    assert_eq!(observed[0].reason_code, "proxy.revision_published");
    assert_eq!(
        observed[0].revision_id.as_ref().unwrap().to_string(),
        revision.revision_id
    );
}
