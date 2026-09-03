use async_trait::async_trait;

use crate::{
    ApprovalAction, ApprovalDecision, AuthorizationDecision, AuthorizationRequest, EventReceipt,
    GovernanceError, GovernanceScope, PolicySnapshot, ToolExecutionEvent,
};

/// The Apex authorization and policy lookup boundary used by data-plane adapters.
#[async_trait]
pub trait ApexGovernance: Send + Sync {
    /// Evaluates one fully contextualized request without exposing policy storage.
    async fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, GovernanceError>;

    /// Returns policy identity and revision metadata for an exact scope.
    async fn get_policy(&self, scope: &GovernanceScope) -> Result<PolicySnapshot, GovernanceError>;
}

/// The Apex durable event-admission boundary.
#[async_trait]
pub trait ApexEvents: Send + Sync {
    /// Durably admits metadata-only tool evidence and returns its event ID.
    async fn emit(&self, event: ToolExecutionEvent) -> Result<EventReceipt, GovernanceError>;
}

/// The Apex human-approval boundary for actions that cannot execute immediately.
#[async_trait]
pub trait ApexApproval: Send + Sync {
    /// Submits an already validated action for approval processing.
    async fn request(&self, action: ApprovalAction) -> Result<ApprovalDecision, GovernanceError>;
}
