use apex_control_plane_api::{
    ListProxyActivity, ListProxyActivityPage, McpProxy, McpProxyRevision, ProxyRevisionId,
    ProxySpec, ProxyStoreBackend, validate_proxy_spec,
};

use super::fixtures::{create, edit, portfolio_spec, publish, request_id, unsupported_specs};

#[derive(PartialEq, Eq)]
struct VisibleState {
    proxy: McpProxy,
    draft: McpProxyRevision,
    active: Option<McpProxyRevision>,
    activity: ListProxyActivityPage,
}

fn visible(store: &impl ProxyStoreBackend, proxy: &McpProxy) -> VisibleState {
    let proxy = store
        .get(proxy.scope.clone(), proxy.proxy_id.clone())
        .unwrap();
    let revision = |id| {
        store
            .get_revision(proxy.scope.clone(), proxy.proxy_id.clone(), id)
            .unwrap()
    };
    let draft = revision(proxy.draft_revision_id.clone().unwrap());
    let active = proxy.active_revision_id.clone().map(revision);
    let activity = store
        .list_activity(ListProxyActivity {
            scope: proxy.scope.clone(),
            proxy_id: proxy.proxy_id.clone(),
            page_size: 100,
            page_token: String::new(),
        })
        .unwrap();
    assert!(activity.next_page_token.is_empty());
    VisibleState {
        proxy,
        draft,
        active,
        activity,
    }
}

fn draft(store: &impl ProxyStoreBackend, spec: ProxySpec) -> McpProxy {
    let created = store.create(create()).unwrap();
    store.update_draft(edit(&created, spec)).unwrap()
}

pub fn unsupported_publication<T: PartialEq>(
    store: &impl ProxyStoreBackend,
    snapshot: impl Fn() -> T,
) {
    for (label, spec) in unsupported_specs() {
        // If a future refactor rejects these at draft validation instead, fail:
        // the capability policy belongs only at publication.
        validate_proxy_spec(&spec).expect(label);
        let initial = draft(store, portfolio_spec());
        let original = store.publish_revision(publish(&initial)).unwrap();
        let current = store
            .get(initial.scope.clone(), initial.proxy_id.clone())
            .unwrap();
        let edited = store
            .update_draft(edit(&current, spec.clone()))
            .expect(label);
        assert!(
            edited.spec.as_ref() == Some(&spec),
            "{label}: draft round trip"
        );
        let attempt = publish(&edited);
        let before = visible(store, &edited);
        let persisted = snapshot();

        let result = store.publish_revision(attempt.clone());

        assert!(
            visible(store, &edited) == before,
            "{label}: rejected publication changed visible state"
        );
        assert!(
            snapshot() == persisted,
            "{label}: rejected publication changed persisted rows"
        );
        assert_eq!(
            result.expect_err(label).code(),
            "INVALID_PROXY_SPEC",
            "{label}"
        );
        assert_eq!(
            store
                .get_revision(
                    edited.scope.clone(),
                    edited.proxy_id.clone(),
                    ProxyRevisionId::new(&attempt.request_id).unwrap(),
                )
                .unwrap_err()
                .code(),
            "PROXY_REVISION_NOT_FOUND",
            "{label}"
        );

        // Even after refusal, otherwise valid unsupported metadata remains editable.
        let mut still_unsupported = spec.clone();
        still_unsupported.governance_binding.rate_limit_per_minute = 61;
        let edited_again = store
            .update_draft(edit(&edited, still_unsupported.clone()))
            .expect(label);
        assert!(
            edited_again.spec == Some(still_unsupported),
            "{label}: subsequent draft edit"
        );
        assert!(
            store
                .get_revision(
                    edited.scope.clone(),
                    edited.proxy_id.clone(),
                    attempt.draft_revision_id.clone(),
                )
                .unwrap()
                .spec
                == spec,
            "{label}: older draft mutated"
        );
        assert!(
            store
                .get_revision(
                    edited.scope.clone(),
                    edited.proxy_id.clone(),
                    original.revision_id.clone(),
                )
                .unwrap()
                == original,
            "{label}: published revision mutated"
        );

        let repaired = store
            .update_draft(edit(&edited_again, portfolio_spec()))
            .unwrap();
        let mut retry = publish(&repaired);
        retry.request_id = attempt.request_id;
        // Same failed request ID, changed draft: proves no idempotency reservation.
        let published = store.publish_revision(retry.clone()).expect(label);
        assert!(
            published.spec == portfolio_spec(),
            "{label}: repair lost fields"
        );
        let committed = snapshot();
        let visible_committed = visible(store, &repaired);
        assert!(store.publish_revision(retry).unwrap() == published);
        assert!(snapshot() == committed);
        assert!(visible(store, &repaired) == visible_committed);
    }
}

pub fn supported_replay<T: PartialEq>(store: &impl ProxyStoreBackend, snapshot: impl Fn() -> T) {
    let draft = draft(store, portfolio_spec());
    let attempt = publish(&draft);
    let published = store.publish_revision(attempt.clone()).unwrap();
    assert_eq!(published.spec, portfolio_spec());
    assert_ne!(
        published.revision_id,
        draft.draft_revision_id.clone().unwrap()
    );
    let current = store
        .get(draft.scope.clone(), draft.proxy_id.clone())
        .unwrap();
    assert_eq!(
        current.active_revision_id,
        Some(published.revision_id.clone())
    );
    assert_eq!(current.draft_revision_id, draft.draft_revision_id);

    // A later unsupported draft must not invalidate a successful committed replay.
    let unsupported = unsupported_specs()
        .into_iter()
        .find(|(label, _)| *label == "cli_profile")
        .unwrap()
        .1;
    let updated = store.update_draft(edit(&current, unsupported)).unwrap();
    let before = visible(store, &updated);
    let persisted = snapshot();
    assert_eq!(store.publish_revision(attempt.clone()).unwrap(), published);
    assert!(visible(store, &updated) == before);
    assert!(snapshot() == persisted);

    let mut conflict = attempt.clone();
    conflict.actor_id = "operator:someone-else".into();
    assert_eq!(
        store.publish_revision(conflict).unwrap_err().code(),
        "PROXY_IDEMPOTENCY_CONFLICT"
    );
    let mut hidden_replay = attempt;
    hidden_replay.scope.namespace_id = "other-namespace".into();
    assert_eq!(
        store.publish_revision(hidden_replay).unwrap_err().code(),
        "PROXY_NOT_FOUND"
    );
    let mut immutable = publish(&updated);
    immutable.draft_revision_id = published.revision_id;
    assert_eq!(
        store.publish_revision(immutable).unwrap_err().code(),
        "IMMUTABLE_PROXY_REVISION"
    );
    assert!(visible(store, &updated) == before);
    assert!(snapshot() == persisted);
}

pub fn guard_precedence<T: PartialEq>(store: &impl ProxyStoreBackend, snapshot: impl Fn() -> T) {
    let spec = unsupported_specs().remove(0).1;
    let draft = draft(store, spec);
    let before = visible(store, &draft);
    let persisted = snapshot();
    let mut hidden = publish(&draft);
    hidden.scope.workspace_id = "other-workspace".into();
    assert_eq!(
        store.publish_revision(hidden).unwrap_err().code(),
        "PROXY_NOT_FOUND"
    );
    let mut stale = publish(&draft);
    stale.expected_revision_id = Some(ProxyRevisionId::new(request_id()).unwrap());
    assert_eq!(
        store.publish_revision(stale).unwrap_err().code(),
        "PROXY_REVISION_CONFLICT"
    );
    assert!(visible(store, &draft) == before);
    assert!(snapshot() == persisted);
}
