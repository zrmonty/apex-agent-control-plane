# Apex Governance Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a transport-neutral Rust governance boundary that the future MCP gateway can use for authorization, policy lookup, durable tool-event admission, and approvals without owning policy or audit state.

**Architecture:** Create `crates/apex-policy` as a contract-only shared crate. It reuses `apex-domain::Caller` and `is_scope_identifier`, exposes validated request/decision/event records, and defines async object-safe traits for replaceable Apex adapters. Tests provide in-memory fakes; production policy storage, network clients, MCP transport, and approval persistence remain out of scope.

**Tech Stack:** Rust 2024 workspace, `async-trait`, `thiserror`, Tokio test runtime, existing `apex-domain` caller and scope validation primitives.

**Spec:** `docs/superpowers/specs/2026-09-03-apex-mcp-vertical-slice-design.md`, sections 5, 7, 8, and 9; execution source `docs/roadmap.md`, milestone 3.

## Global Constraints

- Apex remains the policy, approval, audit, and durable-event authority; the contract crate stores none of those authorities.
- Requests must carry authenticated principal, exact workspace/namespace scope, tool, action, resource, classification, and trace context.
- Decisions must make allow, deny, approval, policy identity, safe reason code, and field restrictions explicit.
- Tool events contain metadata, sizes, filtering actions, policy result, and trace identifiers only; never raw prompts, client records, tool payloads, or responses.
- Event admission means durable Apex acceptance, not downstream NATS, ClickHouse, archive, or processor completion.
- Invalid or unauthorized scope/identifier input fails before an adapter call and exposes no untrusted value in the error text.
- Public enums and records must be documented and forward-compatible where future variants or fields are plausible.
- Every production behavior change follows RED → GREEN → REFACTOR, with the failing test observed before implementation.
- Keep the current workspace applications and protobuf contracts behaviorally unchanged.

---

### Task 1: Scaffold the policy contract crate and validated boundary values

**Files:**
- Create: `crates/apex-policy/Cargo.toml`
- Create: `crates/apex-policy/src/lib.rs`
- Create: `crates/apex-policy/src/error.rs`
- Create: `crates/apex-policy/src/types.rs`
- Create: `crates/apex-policy/src/tests.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Consumes: `apex_domain::{Caller, is_scope_identifier}`.
- Produces: `GovernanceScope`, `GovernanceInputError`, `IdentifierKind`, `ToolName`, `ActionName`, `ResourceName`, `PolicyId`, `ReasonCode`, `BackendName`, `FieldPath`, `TraceId`, `SpanId`, `RunId`, `EventId`, and `TraceContext`.

- [ ] **Step 1: Add the failing boundary tests**

Add tests that use the intended constructors:

```rust
#[test]
fn valid_scope_and_trace_context_preserve_safe_metadata() {
    let scope = GovernanceScope::new("acme", "prod").unwrap();
    let trace = TraceContext::new(
        "trace-1",
        Some("span-1"),
        Some("parent-1"),
        Some("run-1"),
    )
    .unwrap();

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
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p apex-policy valid_scope_and_trace_context_preserve_safe_metadata -- --exact`

Expected: compilation failure because the new public types and crate member do not exist yet.

- [ ] **Step 3: Add the crate scaffold and minimal typed implementations**

Add the workspace member and crate manifest. Implement private-string validated newtypes with `new`, `as_str`, and `into_string`; use the existing identifier grammar for tool/action/resource/policy/reason/backend/trace values and the existing lowercase UUIDv7 validator for `EventId`. Implement `GovernanceScope::new`, `workspace_id`, `namespace_id`, and `key`; reject invalid caller-independent scope values without retaining or formatting the input in errors. Implement `TraceContext::new` with required `TraceId` and optional span/parent-span/run IDs.

Use this public error shape:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceInputError {
    #[error("invalid governance scope")]
    InvalidScope,
    #[error("invalid authenticated principal")]
    InvalidPrincipal,
    #[error("authenticated principal is not authorized for the requested scope")]
    ScopeNotAllowed,
    #[error("invalid governance identifier")]
    InvalidIdentifier { kind: IdentifierKind },
}
```

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p apex-policy valid_scope_and_trace_context_preserve_safe_metadata invalid_scope_and_identifier_values_fail_without_echoing_input`

Expected: PASS with both tests green.

- [ ] **Step 5: Refactor and commit the self-contained boundary**

Run: `cargo fmt --all -- --check` and `cargo test -p apex-policy`.

Commit: `git add Cargo.toml Cargo.lock crates/apex-policy && git commit -m "feat: add Apex governance boundary types"`

### Task 2: Add authorization, policy, approval, and safe failure contracts

**Files:**
- Modify: `crates/apex-policy/src/types.rs`
- Modify: `crates/apex-policy/src/error.rs`
- Modify: `crates/apex-policy/src/lib.rs`
- Modify: `crates/apex-policy/src/tests.rs`

**Interfaces:**
- Consumes: Task 1 validated identifiers, `GovernanceScope`, `TraceContext`, and `apex_domain::Caller`.
- Produces: `DataClassification`, `AuthorizationRequest`, `AuthorizationOutcome`, `AuthorizationDecision`, `PolicySnapshot`, `ApprovalAction`, `ApprovalOutcome`, `ApprovalDecision`, and `GovernanceError`.

- [ ] **Step 1: Write failing authorization and approval contract tests**

Add tests for exact scope binding, classification/policy metadata, allow/deny/approval outcomes, and future-safe policy lookup:

```rust
#[test]
fn authorization_request_requires_the_callers_exact_scope() {
    let caller = Caller::authenticated_for_agent("spiffe://apex/test", "agent-1", ["acme/prod"])
        .unwrap();
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
    assert!(AuthorizationRequest::new(
        caller,
        GovernanceScope::new("other", "prod").unwrap(),
        ToolName::new("portfolio.read").unwrap(),
        ActionName::new("read").unwrap(),
        ResourceName::new("portfolio:alpha").unwrap(),
        DataClassification::Confidential,
        TraceContext::new("trace-2", None, None, None).unwrap(),
    )
    .is_err());
}

#[test]
fn authorization_decision_exposes_policy_reason_and_field_restrictions() {
    let policy_id = PolicyId::new("ria-read-v1").unwrap();
    let reason = ReasonCode::new("policy.allowed").unwrap();
    let restricted = vec![FieldPath::new("client.account_number").unwrap()];
    let decision = AuthorizationDecision::allow(policy_id.clone(), reason.clone(), restricted.clone());

    assert!(decision.is_allowed());
    assert_eq!(decision.outcome(), AuthorizationOutcome::Allowed);
    assert_eq!(decision.policy_id(), &policy_id);
    assert_eq!(decision.reason_code(), &reason);
    assert_eq!(decision.field_restrictions(), restricted.as_slice());
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p apex-policy authorization_request_requires_the_callers_exact_scope -- --exact`

Expected: compilation failure because the authorization records do not exist yet.

- [ ] **Step 3: Implement the minimal authorization and approval records**

Implement `AuthorizationRequest::new` so it rejects invalid callers and checks `caller.allows_scope(&scope.key())` before constructing the request. Keep principal and scope accessors read-only. Use `#[non_exhaustive]` on public outcome/classification enums where extension is plausible. Implement constructors for `AuthorizationDecision::allow`, `deny`, and `requires_approval`; `is_allowed` returns true only for an allowed outcome, never for deny or approval-pending. Implement `PolicySnapshot` with scope, policy ID, and monotonically comparable revision metadata. Define `ApprovalAction` from an authorization request plus a safe reason code, and `ApprovalDecision` with `Pending`, `Approved`, and `Denied` outcomes.

Implement typed, content-free operational errors:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceError {
    #[error("authorization service unavailable")]
    AuthorizationUnavailable,
    #[error("policy service unavailable")]
    PolicyUnavailable,
    #[error("durable event admission failed")]
    EventAdmissionFailed,
    #[error("approval service unavailable")]
    ApprovalUnavailable,
    #[error("governance service failed")]
    Internal,
}

impl GovernanceError {
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::AuthorizationUnavailable
                | Self::PolicyUnavailable
                | Self::EventAdmissionFailed
                | Self::ApprovalUnavailable
        )
    }
}
```

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test -p apex-policy authorization_request_requires_the_callers_exact_scope authorization_decision_exposes_policy_reason_and_field_restrictions`

Expected: PASS, including assertions that invalid scope errors remain content-free.

- [ ] **Step 5: Add edge-case tests, run them, and commit**

Test anonymous callers, invalid authenticated callers, each classification variant, approval-pending behavior, policy revisions, and every `GovernanceError` display/retryability mapping. Run `cargo test -p apex-policy`.

Commit: `git add crates/apex-policy && git commit -m "feat: define Apex authorization and approval contracts"`

### Task 3: Add tool execution evidence and replaceable async interfaces

**Files:**
- Create: `crates/apex-policy/src/traits.rs`
- Modify: `crates/apex-policy/Cargo.toml`
- Modify: `crates/apex-policy/src/types.rs`
- Modify: `crates/apex-policy/src/lib.rs`
- Modify: `crates/apex-policy/src/tests.rs`

**Interfaces:**
- Consumes: Tasks 1–2 request, decision, identifier, trace, and error contracts.
- Produces: `ToolExecutionStatus`, `DataSizeSummary`, `FilteringSummary`, `ToolExecutionEvent`, `EventReceipt`, `ApexGovernance`, `ApexEvents`, and `ApexApproval`.

- [ ] **Step 1: Write failing async contract tests and test adapters**

Add `async-trait` and Tokio test dependencies in the manifest, then write tests against trait objects and in-memory fakes:

```rust
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
        BackendName::new("portfolio-db").unwrap(),
        ToolExecutionStatus::Succeeded,
        12,
        1,
        DataSizeSummary::new(320, 6400, 1800, 1800),
        FilteringSummary::new(vec![FieldPath::new("client.account_number").unwrap()]),
    );
    let events: Box<dyn ApexEvents> = Box::new(RecordingEvents::with_event_id(
        "018f5c91-2d88-7c00-8000-000000000001",
    ));
    let receipt = events.emit(event.clone()).await.unwrap();

    assert_eq!(receipt.event_id().as_str(), "018f5c91-2d88-7c00-8000-000000000001");
    assert_eq!(event.sizes().output_bytes(), 1800);
    assert_eq!(event.filtering().removed_fields().len(), 1);
    assert!(!format!("{event:?}").contains("raw-client-record"));
}
```

The test fake must implement the real traits, record only the typed event, return a validated receipt, and provide explicit unavailable/error variants for failure-path tests.

- [ ] **Step 2: Run the focused async test and verify RED**

Run: `cargo test -p apex-policy governance_event_and_approval_traits_are_replaceable_and_content_free -- --exact`

Expected: compilation failure because the event records and async traits do not exist yet.

- [ ] **Step 3: Implement evidence records and object-safe traits**

Implement `DataSizeSummary` for input/source/filtered/output byte counts and `FilteringSummary` for validated removed field paths. Implement `ToolExecutionEvent::new` from the authorization request, decision, backend, status, latency, retries, sizes, and filtering metadata; copy only safe identity/scope/tool/action/resource/policy/trace metadata. Implement `EventReceipt` around validated lowercase UUIDv7 `EventId`.

Define async object-safe traits with `async-trait`:

```rust
#[async_trait::async_trait]
pub trait ApexGovernance: Send + Sync {
    async fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, GovernanceError>;

    async fn get_policy(
        &self,
        scope: &GovernanceScope,
    ) -> Result<PolicySnapshot, GovernanceError>;
}

#[async_trait::async_trait]
pub trait ApexEvents: Send + Sync {
    async fn emit(&self, event: ToolExecutionEvent) -> Result<EventReceipt, GovernanceError>;
}

#[async_trait::async_trait]
pub trait ApexApproval: Send + Sync {
    async fn request(&self, action: ApprovalAction) -> Result<ApprovalDecision, GovernanceError>;
}
```

- [ ] **Step 4: Run all crate tests and verify GREEN**

Run: `cargo test -p apex-policy`.

Expected: PASS for allow, deny, approval, scope isolation, safe errors, event metadata, UUID receipt validation, and dynamic trait-object adapters.

- [ ] **Step 5: Run quality checks and commit**

Run: `cargo fmt --all -- --check`, `cargo clippy -p apex-policy --all-targets -- -D warnings`, and `cargo test -p apex-policy`.

Commit: `git add crates/apex-policy Cargo.lock && git commit -m "feat: expose Apex governance adapter traits"`

### Task 4: Record the milestone and run full workspace verification

**Files:**
- Modify: `docs/roadmap.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `crates/apex-policy/src/lib.rs` if documentation gaps are found

**Interfaces:**
- Consumes: the complete `apex-policy` public API and all existing workspace applications.
- Produces: documented milestone completion and evidence that the existing workspace/dependency-direction gate remains green.

- [ ] **Step 1: Document the completed governance-contract checkpoint**

Update only the current-status section of `docs/roadmap.md`, `README.md`, and `CLAUDE.md` to state that governance contracts and test adapters are present, while the TypeScript MCP gateway, live Apex adapter, portfolio tool, and operator-visible slice remain next. Do not mark the vertical slice complete.

- [ ] **Step 2: Run the full verification suite**

Run:

```text
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all workspace tests and clippy checks pass, with no whitespace errors.

- [ ] **Step 3: Review the diff and commit the checkpoint**

Confirm no MCP service, policy database, UI route, trade capability, or unrelated roadmap work was added. Commit: `git add docs/roadmap.md README.md CLAUDE.md && git commit -m "docs: record governance contract milestone"`.
