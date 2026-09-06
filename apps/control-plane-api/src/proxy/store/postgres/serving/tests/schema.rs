use super::*;

#[test]
fn schema_refuses_empty_unversioned_newer_or_partial_registry() {
    for change in [
        "DELETE FROM mcp_proxy_serving_schema",
        "DROP TABLE mcp_proxy_serving_schema",
        "ALTER TABLE mcp_proxy_serving_schema DROP CONSTRAINT mcp_proxy_serving_schema_version_check; UPDATE mcp_proxy_serving_schema SET version=2",
        "DROP TABLE mcp_proxy_grant_decisions",
    ] {
        let f = Fixture::new();
        f.client().batch_execute(change).unwrap();
        assert!(PostgresProxyStore::connect(&f.url).is_err(), "{change}");
    }
}

#[test]
fn original_publication_capability_refusal_remains_enabled() {
    let f = Fixture::new();
    let target = f.registration.binding.target.as_ref().unwrap();
    let scope = crate::ExactScope {
        workspace_id: target.workspace_id.clone(),
        namespace_id: target.namespace_id.clone(),
    };
    let proxy = crate::ProxyId::new(&target.proxy_id).unwrap();
    let mut unsupported =
        crate::ProxySpec::try_from(f.registration.configuration.spec.clone().unwrap()).unwrap();
    unsupported.governance_binding.approval_mode = crate::ApprovalMode::Operator;
    use crate::ProxyStore;
    let current = f.store.get(scope.clone(), proxy.clone()).unwrap();
    let draft = f
        .store
        .update_draft(crate::UpdateProxyDraft {
            request_id: Uuid::now_v7().to_string(),
            scope: scope.clone(),
            proxy_id: proxy.clone(),
            expected_revision_id: current.draft_revision_id,
            actor_id: "operator".into(),
            spec: unsupported,
        })
        .unwrap();
    assert!(
        f.store
            .publish_revision(crate::PublishRevision {
                request_id: Uuid::now_v7().to_string(),
                scope,
                proxy_id: proxy,
                draft_revision_id: draft.draft_revision_id.unwrap(),
                expected_revision_id: Some(
                    crate::ProxyRevisionId::new(&target.revision_id).unwrap()
                ),
                actor_id: "operator".into(),
            })
            .is_err()
    );
}
