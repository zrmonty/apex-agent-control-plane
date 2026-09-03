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

fn test_authorization_request() -> AuthorizationRequest {
    let caller =
        Caller::authenticated_for_agent("spiffe://apex/test", "agent-1", ["acme/prod"]).unwrap();
    AuthorizationRequest::new(
        caller,
        GovernanceScope::new("acme", "prod").unwrap(),
        ToolName::new("portfolio.read").unwrap(),
        ActionName::new("read").unwrap(),
        ResourceName::new("portfolio:alpha").unwrap(),
        DataClassification::Confidential,
        TraceContext::new("trace-1", None, None, Some("run-1")).unwrap(),
    )
    .unwrap()
}

struct RecordingGovernance {
    decision: AuthorizationDecision,
    policy: PolicySnapshot,
}

#[async_trait::async_trait]
impl ApexGovernance for RecordingGovernance {
    async fn authorize(
        &self,
        _request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, GovernanceError> {
        Ok(self.decision.clone())
    }

    async fn get_policy(
        &self,
        _scope: &GovernanceScope,
    ) -> Result<PolicySnapshot, GovernanceError> {
        Ok(self.policy.clone())
    }
}

struct RecordingEvents {
    event_id: EventId,
}

impl RecordingEvents {
    fn with_event_id(value: &str) -> Self {
        Self {
            event_id: EventId::new(value).unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl ApexEvents for RecordingEvents {
    async fn emit(&self, _event: ToolExecutionEvent) -> Result<EventReceipt, GovernanceError> {
        Ok(EventReceipt::new(self.event_id.clone()))
    }
}

struct RecordingApproval;

#[async_trait::async_trait]
impl ApexApproval for RecordingApproval {
    async fn request(&self, _action: ApprovalAction) -> Result<ApprovalDecision, GovernanceError> {
        Ok(ApprovalDecision::pending())
    }
}

#[tokio::test]
async fn governance_event_and_approval_traits_are_replaceable_and_content_free() {
    let request = test_authorization_request();
    let decision = AuthorizationDecision::allow(
        PolicyId::new("ria-read-v1").unwrap(),
        ReasonCode::new("policy.allowed").unwrap(),
        vec![FieldPath::new("client.account_number").unwrap()],
    );
    let event = ToolExecutionEvent::new(
        &request,
        &decision,
        ToolExecutionMetadata::new(
            BackendName::new("portfolio-db").unwrap(),
            ToolExecutionStatus::Succeeded,
            12,
            1,
            DataSizeSummary::new(320, 6400, 1800, 1800),
            FilteringSummary::new(vec![FieldPath::new("client.account_number").unwrap()]),
        ),
    );
    let events: Box<dyn ApexEvents> = Box::new(RecordingEvents::with_event_id(
        "018f5c91-2d88-7c00-8000-000000000001",
    ));
    let receipt = events.emit(event.clone()).await.unwrap();
    let governance: Box<dyn ApexGovernance> = Box::new(RecordingGovernance {
        decision: decision.clone(),
        policy: PolicySnapshot::new(
            request.scope().clone(),
            PolicyId::new("ria-read-v1").unwrap(),
            7,
        ),
    });
    let approval: Box<dyn ApexApproval> = Box::new(RecordingApproval);

    let authorized = governance.authorize(request.clone()).await.unwrap();
    let policy = governance.get_policy(request.scope()).await.unwrap();
    let approval_result = approval
        .request(ApprovalAction::new(
            request,
            ReasonCode::new("policy.approval_required").unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(
        receipt.event_id().as_str(),
        "018f5c91-2d88-7c00-8000-000000000001"
    );
    assert_eq!(event.sizes().output_bytes(), 1800);
    assert_eq!(event.filtering().removed_fields().len(), 1);
    assert_eq!(authorized, decision);
    assert_eq!(policy.revision(), 7);
    assert_eq!(approval_result.outcome(), ApprovalOutcome::Pending);
    assert!(!format!("{event:?}").contains("raw-client-record"));
}
