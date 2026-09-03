use apex_domain::Caller;

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

#[test]
fn authorization_request_requires_the_callers_exact_scope() {
    let caller =
        Caller::authenticated_for_agent("spiffe://apex/test", "agent-1", ["acme/prod"]).unwrap();
    let request = AuthorizationRequest::new(
        caller.clone(),
        GovernanceScope::new("acme", "prod").unwrap(),
        ToolName::new("portfolio.read").unwrap(),
        ActionName::new("read").unwrap(),
        ResourceName::new("portfolio:alpha").unwrap(),
        DataClassification::Confidential,
        TraceContext::new("trace-1", None, None, Some("run-1")).unwrap(),
    )
    .unwrap();

    assert_eq!(request.caller().subject(), Some("spiffe://apex/test"));
    assert_eq!(request.scope().key(), "acme/prod");
    assert_eq!(request.classification(), DataClassification::Confidential);
    assert!(
        AuthorizationRequest::new(
            caller,
            GovernanceScope::new("other", "prod").unwrap(),
            ToolName::new("portfolio.read").unwrap(),
            ActionName::new("read").unwrap(),
            ResourceName::new("portfolio:alpha").unwrap(),
            DataClassification::Confidential,
            TraceContext::new("trace-2", None, None, None).unwrap(),
        )
        .is_err()
    );
}

#[test]
fn authorization_decision_exposes_policy_reason_and_field_restrictions() {
    let policy_id = PolicyId::new("ria-read-v1").unwrap();
    let reason = ReasonCode::new("policy.allowed").unwrap();
    let restricted = vec![FieldPath::new("client.account_number").unwrap()];
    let decision =
        AuthorizationDecision::allow(policy_id.clone(), reason.clone(), restricted.clone());

    assert!(decision.is_allowed());
    assert_eq!(decision.outcome(), AuthorizationOutcome::Allowed);
    assert_eq!(decision.policy_id(), &policy_id);
    assert_eq!(decision.reason_code(), &reason);
    assert_eq!(decision.field_restrictions(), restricted.as_slice());
}

#[test]
fn approval_and_operational_errors_have_explicit_safe_status() {
    let approval = AuthorizationDecision::requires_approval(
        PolicyId::new("ria-read-v1").unwrap(),
        ReasonCode::new("policy.approval_required").unwrap(),
    );
    let pending = ApprovalDecision::pending();

    assert!(approval.is_approval_required());
    assert!(!approval.is_allowed());
    assert_eq!(pending.outcome(), ApprovalOutcome::Pending);
    assert_eq!(
        GovernanceError::EventAdmissionFailed.as_str(),
        "EVENT_ADMISSION_FAILED"
    );
    assert!(GovernanceError::EventAdmissionFailed.is_retryable());
    assert!(!GovernanceError::Internal.is_retryable());
}
