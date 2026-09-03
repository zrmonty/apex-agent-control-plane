use super::*;

#[test]
fn valid_scope_and_trace_context_preserve_safe_metadata() {
    let scope = GovernanceScope::new("acme", "prod").unwrap();
    let trace =
        TraceContext::new("trace-1", Some("span-1"), Some("parent-1"), Some("run-1")).unwrap();

    assert_eq!(scope.workspace_id(), "acme");
    assert_eq!(scope.namespace_id(), "prod");
    assert_eq!(scope.key(), "acme/prod");
    assert_eq!(trace.trace_id().as_str(), "trace-1");
    assert_eq!(trace.run_id().unwrap().as_str(), "run-1");
}

#[test]
fn invalid_scope_and_identifier_values_fail_without_echoing_input() {
    let scope_error = GovernanceScope::new("acme/../other", "prod").unwrap_err();
    let identifier_error = ToolName::new("portfolio read").unwrap_err();

    assert_eq!(scope_error, GovernanceInputError::InvalidScope);
    assert_eq!(identifier_error.kind(), IdentifierKind::ToolName);
    assert!(!scope_error.to_string().contains("acme"));
    assert!(!identifier_error.to_string().contains("portfolio read"));
}
