use super::*;
use crate::ExactScope;

fn scope(workspace: &str, namespace: &str) -> ExactScope {
    ExactScope {
        workspace_id: workspace.into(),
        namespace_id: namespace.into(),
    }
}

fn pairs(scopes: Vec<ExactScope>) -> Vec<(String, String)> {
    scopes
        .into_iter()
        .map(|s| (s.workspace_id, s.namespace_id))
        .collect()
}

#[test]
fn scope_choices_only_disclose_exact_verified_grants_in_stable_order() {
    let caller = OperatorCaller::scoped(
        "operator:alice",
        ["zeta/test", "acme/prod", "acme/prod", "acme/dev"],
    )
    .unwrap();
    let choices = caller
        .scope_choices(&[scope("unauthorized", "prod")])
        .unwrap();
    for choice in &choices {
        assert!(caller.allows_scope(&choice.workspace_id, &choice.namespace_id));
    }
    assert_eq!(
        pairs(choices),
        vec![
            ("acme".into(), "dev".into()),
            ("acme".into(), "prod".into()),
            ("zeta".into(), "test".into()),
        ]
    );
}

#[test]
fn scope_choices_for_global_callers_require_concrete_server_catalog() {
    let caller = OperatorCaller::global("operator:breakglass").unwrap();
    assert!(caller.scope_choices(&[]).unwrap().is_empty());
    assert_eq!(
        pairs(
            caller
                .scope_choices(&[
                    scope("zeta", "test"),
                    scope("acme", "prod"),
                    scope("acme", "prod"),
                ])
                .unwrap()
        ),
        vec![
            ("acme".into(), "prod".into()),
            ("zeta".into(), "test".into()),
        ]
    );
}

#[test]
fn scope_choices_never_expand_an_empty_scoped_grant() {
    let caller = OperatorCaller::scoped("operator:empty", Vec::<String>::new()).unwrap();
    assert!(
        caller
            .scope_choices(&[scope("acme", "prod")])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn scope_choices_reject_invalid_or_oversized_catalog_without_echoing_it() {
    let caller = OperatorCaller::global("operator:breakglass").unwrap();
    for candidate in [
        scope("*", "prod"),
        scope("acme", "*"),
        scope("", "prod"),
        scope("secret value", "prod"),
        scope("acme", "../private"),
        scope("acme", "prod/extra"),
        scope("acme", &"x".repeat(257)),
    ] {
        let error = caller.scope_choices(&[candidate]).unwrap_err();
        assert_eq!(error.code, crate::CommandErrorCode::InvalidAuthorization);
        assert!(!format!("{error:?}").contains("secret value"));
    }
    assert!(
        caller
            .scope_choices(&vec![scope("acme", "prod"); 257])
            .is_err()
    );
}

#[test]
fn scope_choices_preserve_the_exact_capacity_and_do_not_mutate_authority() {
    let caller = OperatorCaller::scoped("operator:alice", ["acme/prod"]).unwrap();
    let choices = caller.scope_choices(&[]).unwrap();
    assert_eq!(choices.len(), 1);
    let global = OperatorCaller::global("operator:global").unwrap();
    let catalog: Vec<_> = (0..256).map(|i| scope("acme", &format!("ns{i}"))).collect();
    assert_eq!(global.scope_choices(&catalog).unwrap().len(), 256);
    assert!(!caller.allows_scope("acme", "dev"));
    assert_eq!(caller.subject(), "operator:alice");
}
