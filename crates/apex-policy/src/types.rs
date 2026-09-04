use apex_domain::{Caller, is_lowercase_uuidv7, is_scope_identifier};

use crate::{GovernanceInputError, IdentifierKind};

macro_rules! validated_identifier {
    ($name:ident, $kind:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses a bounded identifier without retaining invalid input.
            pub fn new(value: impl Into<String>) -> Result<Self, GovernanceInputError> {
                let value = value.into();
                if is_scope_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(GovernanceInputError::InvalidIdentifier {
                        kind: IdentifierKind::$kind,
                    })
                }
            }

            /// Returns the validated identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns the validated identifier as an owned string.
            pub fn into_string(self) -> String {
                self.0
            }
        }
    };
}
validated_identifier!(ToolName, ToolName, "A validated MCP or tool-registry name.");
validated_identifier!(
    ActionName,
    ActionName,
    "A validated action name for a tool call."
);
validated_identifier!(
    ResourceName,
    ResourceName,
    "A validated resource reference addressed by a tool call."
);
validated_identifier!(PolicyId, PolicyId, "A validated policy identity.");
validated_identifier!(
    ReasonCode,
    ReasonCode,
    "A validated machine-readable policy reason code."
);
validated_identifier!(BackendName, BackendName, "A validated backend identity.");
validated_identifier!(
    FieldPath,
    FieldPath,
    "A validated field path used by response filtering."
);
validated_identifier!(
    TraceId,
    TraceId,
    "A validated distributed trace identifier."
);
validated_identifier!(
    SpanId,
    SpanId,
    "A validated distributed-trace span identifier."
);
validated_identifier!(RunId, RunId, "A validated agent run identifier.");

/// A validated UUIDv7 identifier allocated to a durably admitted Apex event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(String);

impl EventId {
    /// Parses a lowercase UUIDv7 event identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, GovernanceInputError> {
        let value = value.into();
        if is_lowercase_uuidv7(&value) {
            Ok(Self(value))
        } else {
            Err(GovernanceInputError::InvalidIdentifier {
                kind: IdentifierKind::EventId,
            })
        }
    }

    /// Returns the event identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated workspace and namespace pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GovernanceScope {
    workspace_id: String,
    namespace_id: String,
}

impl GovernanceScope {
    /// Creates a scope from validated workspace and namespace identifiers.
    pub fn new(
        workspace_id: impl Into<String>,
        namespace_id: impl Into<String>,
    ) -> Result<Self, GovernanceInputError> {
        let workspace_id = workspace_id.into();
        let namespace_id = namespace_id.into();
        if !is_scope_identifier(&workspace_id) || !is_scope_identifier(&namespace_id) {
            return Err(GovernanceInputError::InvalidScope);
        }
        Ok(Self {
            workspace_id,
            namespace_id,
        })
    }

    /// Returns the validated workspace identifier.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Returns the validated namespace identifier.
    pub fn namespace_id(&self) -> &str {
        &self.namespace_id
    }

    /// Returns the canonical scope key used by the existing caller boundary.
    pub fn key(&self) -> String {
        format!("{}/{}", self.workspace_id, self.namespace_id)
    }
}

/// Distributed trace and optional run correlation carried through governance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceContext {
    trace_id: TraceId,
    span_id: Option<SpanId>,
    parent_span_id: Option<SpanId>,
    run_id: Option<RunId>,
}

impl TraceContext {
    /// Creates a trace context with a required trace ID and optional span/run IDs.
    pub fn new<T>(
        trace_id: T,
        span_id: Option<T>,
        parent_span_id: Option<T>,
        run_id: Option<T>,
    ) -> Result<Self, GovernanceInputError>
    where
        T: Into<String>,
    {
        Ok(Self {
            trace_id: TraceId::new(trace_id)?,
            span_id: span_id.map(SpanId::new).transpose()?,
            parent_span_id: parent_span_id.map(SpanId::new).transpose()?,
            run_id: run_id.map(RunId::new).transpose()?,
        })
    }

    /// Returns the required trace identifier.
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the optional current span identifier.
    pub fn span_id(&self) -> Option<&SpanId> {
        self.span_id.as_ref()
    }

    /// Returns the optional parent span identifier.
    pub fn parent_span_id(&self) -> Option<&SpanId> {
        self.parent_span_id.as_ref()
    }

    /// Returns the optional agent run identifier.
    pub fn run_id(&self) -> Option<&RunId> {
        self.run_id.as_ref()
    }
}

/// The data sensitivity class supplied to policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataClassification {
    /// Data safe for unrestricted distribution.
    Public,
    /// Data intended for an organization's internal use.
    Internal,
    /// Sensitive business or client data requiring controlled access.
    Confidential,
    /// Highly sensitive data requiring the strongest policy safeguards.
    Restricted,
}

/// The result of evaluating a governance request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthorizationOutcome {
    /// The tool may execute subject to the returned field restrictions.
    Allowed,
    /// The tool must not execute.
    Denied,
    /// The tool must wait for an approval decision before it may execute.
    RequiresApproval,
}

/// A fully contextualized, authenticated request sent to Apex governance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    caller: Caller,
    scope: GovernanceScope,
    tool: ToolName,
    action: ActionName,
    resource: ResourceName,
    classification: DataClassification,
    trace: TraceContext,
}

impl AuthorizationRequest {
    /// Creates a request after validating the caller and binding it to an exact scope.
    pub fn new(
        caller: Caller,
        scope: GovernanceScope,
        tool: ToolName,
        action: ActionName,
        resource: ResourceName,
        classification: DataClassification,
        trace: TraceContext,
    ) -> Result<Self, GovernanceInputError> {
        if !caller.is_valid() {
            return Err(GovernanceInputError::InvalidPrincipal);
        }
        if !caller.allows_scope(&scope.key()) {
            return Err(GovernanceInputError::ScopeNotAllowed);
        }
        Ok(Self {
            caller,
            scope,
            tool,
            action,
            resource,
            classification,
            trace,
        })
    }

    /// Returns the authenticated principal and its existing Apex scope claims.
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// Returns the exact workspace/namespace scope being requested.
    pub fn scope(&self) -> &GovernanceScope {
        &self.scope
    }

    /// Returns the tool being requested.
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// Returns the action being requested.
    pub fn action(&self) -> &ActionName {
        &self.action
    }

    /// Returns the resource being requested.
    pub fn resource(&self) -> &ResourceName {
        &self.resource
    }

    /// Returns the classification presented to policy evaluation.
    pub fn classification(&self) -> DataClassification {
        self.classification
    }

    /// Returns the distributed-trace and run correlation context.
    pub fn trace(&self) -> &TraceContext {
        &self.trace
    }
}

/// An immutable policy decision returned by Apex governance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    outcome: AuthorizationOutcome,
    policy_id: PolicyId,
    reason_code: ReasonCode,
    field_restrictions: Vec<FieldPath>,
}

impl AuthorizationDecision {
    /// Creates an allowed decision with policy-driven field restrictions.
    pub fn allow(
        policy_id: PolicyId,
        reason_code: ReasonCode,
        field_restrictions: Vec<FieldPath>,
    ) -> Self {
        Self {
            outcome: AuthorizationOutcome::Allowed,
            policy_id,
            reason_code,
            field_restrictions,
        }
    }

    /// Creates a denial decision with no executable field permissions.
    pub fn deny(policy_id: PolicyId, reason_code: ReasonCode) -> Self {
        Self {
            outcome: AuthorizationOutcome::Denied,
            policy_id,
            reason_code,
            field_restrictions: Vec::new(),
        }
    }

    /// Creates a decision that requires approval before execution.
    pub fn requires_approval(policy_id: PolicyId, reason_code: ReasonCode) -> Self {
        Self {
            outcome: AuthorizationOutcome::RequiresApproval,
            policy_id,
            reason_code,
            field_restrictions: Vec::new(),
        }
    }

    /// Returns the policy outcome.
    pub fn outcome(&self) -> AuthorizationOutcome {
        self.outcome
    }

    /// Returns whether the caller may execute without a separate approval.
    pub fn is_allowed(&self) -> bool {
        self.outcome == AuthorizationOutcome::Allowed
    }

    /// Returns whether execution must wait for an approval decision.
    pub fn is_approval_required(&self) -> bool {
        self.outcome == AuthorizationOutcome::RequiresApproval
    }

    /// Returns the policy identity that produced this decision.
    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    /// Returns the safe machine-readable reason code.
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }

    /// Returns the fields that the caller must not receive.
    pub fn field_restrictions(&self) -> &[FieldPath] {
        &self.field_restrictions
    }
}

/// A policy identity and revision for an exact scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    scope: GovernanceScope,
    policy_id: PolicyId,
    revision: u64,
}

impl PolicySnapshot {
    /// Creates policy metadata returned for a validated scope.
    pub fn new(scope: GovernanceScope, policy_id: PolicyId, revision: u64) -> Self {
        Self {
            scope,
            policy_id,
            revision,
        }
    }

    /// Returns the scope governed by this snapshot.
    pub fn scope(&self) -> &GovernanceScope {
        &self.scope
    }

    /// Returns the policy identity.
    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    /// Returns the policy revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// A high-impact action submitted to the approval boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalAction {
    authorization: AuthorizationRequest,
    reason_code: ReasonCode,
}

impl ApprovalAction {
    /// Creates an approval action from an already validated authorization request.
    pub fn new(authorization: AuthorizationRequest, reason_code: ReasonCode) -> Self {
        Self {
            authorization,
            reason_code,
        }
    }

    /// Returns the authorization context requiring approval.
    pub fn authorization(&self) -> &AuthorizationRequest {
        &self.authorization
    }

    /// Returns the safe reason for requesting approval.
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }
}
