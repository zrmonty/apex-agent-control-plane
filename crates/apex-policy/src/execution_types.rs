use apex_domain::Caller;

use super::{
    ActionName, AuthorizationDecision, AuthorizationRequest, BackendName, EventId, FieldPath,
    GovernanceScope, ResourceName, ToolName, TraceContext,
};

/// The current state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApprovalOutcome {
    /// The approval request is waiting for an authorized human decision.
    Pending,
    /// The approval was granted.
    Approved,
    /// The approval was refused.
    Denied,
}

/// A result returned by the approval boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApprovalDecision {
    outcome: ApprovalOutcome,
}

impl ApprovalDecision {
    /// Creates a pending approval result.
    pub fn pending() -> Self {
        Self::new(ApprovalOutcome::Pending)
    }

    /// Creates an approved result.
    pub fn approved() -> Self {
        Self::new(ApprovalOutcome::Approved)
    }

    /// Creates a denied result.
    pub fn denied() -> Self {
        Self::new(ApprovalOutcome::Denied)
    }

    /// Creates an approval decision with the supplied state.
    pub fn new(outcome: ApprovalOutcome) -> Self {
        Self { outcome }
    }

    /// Returns the approval state.
    pub fn outcome(&self) -> ApprovalOutcome {
        self.outcome
    }
}

/// The outcome of executing a tool after governance processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ToolExecutionStatus {
    /// The tool completed successfully.
    Succeeded,
    /// The request was denied before adapter execution.
    Denied,
    /// The tool adapter failed without exposing backend details.
    Failed,
}

/// Byte counts recorded for a tool execution without retaining its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataSizeSummary {
    input_bytes: u64,
    source_bytes: u64,
    filtered_bytes: u64,
    output_bytes: u64,
}

impl DataSizeSummary {
    /// Creates a size summary for request, source, filtered, and output data.
    pub fn new(
        input_bytes: u64,
        source_bytes: u64,
        filtered_bytes: u64,
        output_bytes: u64,
    ) -> Self {
        Self {
            input_bytes,
            source_bytes,
            filtered_bytes,
            output_bytes,
        }
    }

    /// Returns the request input size in bytes.
    pub fn input_bytes(&self) -> u64 {
        self.input_bytes
    }

    /// Returns the unfiltered backend source size in bytes.
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    /// Returns the post-filter data size in bytes.
    pub fn filtered_bytes(&self) -> u64 {
        self.filtered_bytes
    }

    /// Returns the data size returned to the caller in bytes.
    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }
}

/// A content-free summary of response filtering actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteringSummary {
    removed_fields: Vec<FieldPath>,
}

impl FilteringSummary {
    /// Creates a filtering summary from validated removed field paths.
    pub fn new(removed_fields: Vec<FieldPath>) -> Self {
        Self { removed_fields }
    }

    /// Returns the fields removed before data reached the caller.
    pub fn removed_fields(&self) -> &[FieldPath] {
        &self.removed_fields
    }
}

/// Content-free execution metadata attached to a governed tool event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionMetadata {
    backend: BackendName,
    status: ToolExecutionStatus,
    latency_ms: u64,
    retry_count: u32,
    sizes: DataSizeSummary,
    filtering: FilteringSummary,
}

impl ToolExecutionMetadata {
    /// Creates execution metadata from validated backend and filtering values.
    pub fn new(
        backend: BackendName,
        status: ToolExecutionStatus,
        latency_ms: u64,
        retry_count: u32,
        sizes: DataSizeSummary,
        filtering: FilteringSummary,
    ) -> Self {
        Self {
            backend,
            status,
            latency_ms,
            retry_count,
            sizes,
            filtering,
        }
    }

    /// Returns the backend identity.
    pub fn backend(&self) -> &BackendName {
        &self.backend
    }

    /// Returns the execution outcome.
    pub fn status(&self) -> ToolExecutionStatus {
        self.status
    }

    /// Returns elapsed adapter time in milliseconds.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Returns the number of adapter retries.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the content-free size summary.
    pub fn sizes(&self) -> &DataSizeSummary {
        &self.sizes
    }

    /// Returns the content-free filtering summary.
    pub fn filtering(&self) -> &FilteringSummary {
        &self.filtering
    }
}

/// Metadata-only evidence for one governed tool execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionEvent {
    caller: Caller,
    scope: GovernanceScope,
    tool: ToolName,
    action: ActionName,
    resource: ResourceName,
    backend: BackendName,
    status: ToolExecutionStatus,
    latency_ms: u64,
    retry_count: u32,
    sizes: DataSizeSummary,
    filtering: FilteringSummary,
    policy: AuthorizationDecision,
    trace: TraceContext,
}

impl ToolExecutionEvent {
    /// Builds evidence from an authorized request and its policy decision.
    ///
    /// The event copies only validated identity, scope, tool, policy, trace,
    /// timing, size, and filtering metadata. It has no raw-content fields.
    pub fn new(
        request: &AuthorizationRequest,
        decision: &AuthorizationDecision,
        metadata: ToolExecutionMetadata,
    ) -> Self {
        Self {
            caller: request.caller().clone(),
            scope: request.scope().clone(),
            tool: request.tool().clone(),
            action: request.action().clone(),
            resource: request.resource().clone(),
            backend: metadata.backend,
            status: metadata.status,
            latency_ms: metadata.latency_ms,
            retry_count: metadata.retry_count,
            sizes: metadata.sizes,
            filtering: metadata.filtering,
            policy: decision.clone(),
            trace: request.trace().clone(),
        }
    }

    /// Returns the authenticated principal associated with the event.
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// Returns the exact workspace/namespace scope associated with the event.
    pub fn scope(&self) -> &GovernanceScope {
        &self.scope
    }

    /// Returns the executed or denied tool.
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// Returns the requested action.
    pub fn action(&self) -> &ActionName {
        &self.action
    }

    /// Returns the requested resource.
    pub fn resource(&self) -> &ResourceName {
        &self.resource
    }

    /// Returns the backend identity.
    pub fn backend(&self) -> &BackendName {
        &self.backend
    }

    /// Returns the execution outcome.
    pub fn status(&self) -> ToolExecutionStatus {
        self.status
    }

    /// Returns elapsed adapter time in milliseconds.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Returns the number of adapter retries.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the content-free size summary.
    pub fn sizes(&self) -> &DataSizeSummary {
        &self.sizes
    }

    /// Returns the content-free filtering summary.
    pub fn filtering(&self) -> &FilteringSummary {
        &self.filtering
    }

    /// Returns the policy decision associated with the execution.
    pub fn policy(&self) -> &AuthorizationDecision {
        &self.policy
    }

    /// Returns the distributed-trace and run correlation context.
    pub fn trace(&self) -> &TraceContext {
        &self.trace
    }
}

/// Confirmation that Apex durably admitted a tool execution event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventReceipt {
    event_id: EventId,
}

impl EventReceipt {
    /// Creates a receipt for a validated Apex event identifier.
    pub fn new(event_id: EventId) -> Self {
        Self { event_id }
    }

    /// Returns the durable event identifier.
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
}
