//! Phase 0.5 out-of-band (OOB) control command gateway.
//!
//! Independently authenticated from the `event-ingest` data path (see
//! [`auth`]), this crate exposes the five cooperative v1 controls --
//! `stop`/`pause`/`resume`/`inject`/`set_budget` (ADR-0005) -- plus
//! `resolve_hold`, the shared delivery primitive a held tool call (HITL
//! Approvals' blocking mode, Defense-Evasion Interception's hold tier) uses
//! to get an operator's approve/deny decision back to the agent waiting on
//! it -- behind a durable command outbox (ADR-0006). Every accepted command
//! is validated
//! and canonicalized into a `control` event using the same admission rules
//! `event-ingest` enforces on its data path
//! (`apex_durability::IngestRequest::from_validated_transport`), then
//! durably enqueued so it survives a crash before fanout, and later flows
//! into the same queryable trace as everything else.
//!
//! Durability does not have a hard dependency on JetStream/ClickHouse being
//! reachable: a command is durably accepted once the outbox commits the row,
//! before any downstream fanout is attempted. See [`replay`].
//!
//! A sixth action, `force_stop`, is *not* cooperative (ADR-0005's "Offer
//! forced stop immediately -- rejected until process isolation and a safety
//! model exist" is the v1 decision this closes): it is polled and enacted by
//! a run's `apps/agent-supervisor` process, which holds real OS kill
//! authority and its own distinct workload credential the agent it
//! supervises never has access to, and it is the one action `SubmitCommand`
//! requires two distinct operator approvals to record at all (see the
//! crate-internal `dual_approval` module).

pub mod proto {
    tonic::include_proto!("apex.v1");
    include!(concat!(env!("OUT_DIR"), "/apex.v1.serde.rs"));
}

#[cfg(test)]
mod governance_tests;

mod agent_auth;
mod auth;
pub mod contract_json;
mod dual_approval;
mod envelope;
mod errors;
mod governance;
mod inbox;
mod keycloak;
mod outbox;
mod proxy;
mod replay;
mod service;
mod status;

pub use agent_auth::{
    AgentRevocationError, AgentRevocationList, AgentTokenTableError, AgentWorkloadAuthenticator,
    BoxedAgentWorkloadResolver, RevocationAwareAgentResolver, StaticAgentWorkloadResolver,
    agent_workload_subject, parse_agent_token_table, peer_identity_from_request,
    supervisor_agent_id,
};
pub use auth::{
    BoxedOperatorCredentialResolver, GatewayTokenAuthenticator, OperatorCaller,
    OperatorCredentialResolver, OperatorTokenAuthenticator, OperatorTokenTableError,
    StaticOperatorTokenResolver, parse_operator_token_table,
};
pub use envelope::{
    AcceptedCommand, ControlCommandInput, build_control_request,
    pending_command_from_ingest_request,
};
pub use errors::{CommandError, CommandErrorCode};
pub use governance::{GovernanceConfig, GovernanceGatewayService};
pub use inbox::{
    AckResult, CancelResult, CommandInbox, CommandSummary, ControlInboxBackend,
    DEFAULT_INBOX_CAPACITY, DEFAULT_INBOX_SCOPE_QUOTA, DEFAULT_LIST_COMMANDS_PAGE_SIZE,
    DEFAULT_MAX_COMMANDS_PER_POLL, DEFAULT_MAX_DELIVERY_ATTEMPTS, DEFAULT_REDELIVERY_AFTER,
    DeliveryPolicy, DeliveryStatus, ExactScope, FileCommandInbox, InMemoryCommandInbox, InboxKey,
    ListCommandsPage, ListCommandsQuery, MAX_COMMANDS_PER_POLL, MAX_LIST_COMMANDS_PAGE_SIZE,
    PendingCommand, PollTarget, RecordResult, ScopeAuthorizer,
};
#[cfg(feature = "postgres")]
pub use inbox::{PostgresCommandInbox, RecoveringPostgresCommandInbox};
pub use keycloak::{
    KeycloakConfig, KeycloakConfigError, KeycloakOperatorCredentialResolver, KeycloakRejection,
};
#[cfg(feature = "postgres")]
pub use outbox::RecoveringPostgresOutbox;
pub use outbox::{ControlOutboxBackend, submit_command};
#[cfg(feature = "postgres")]
pub use proxy::PostgresProxyStore;
pub use proxy::{
    ApprovalMode, ArgSchema, ArgSchemaField, AuthBinding, CliProfile, CreateProxy,
    CreateProxyResult, DataClassification, EgressDestination, ExposedTool, GovernanceBinding,
    InMemoryProxyStore, Ingress, ListProxies, ListProxiesPage, ListProxyActivity,
    ListProxyActivityPage, McpProxy, McpProxyRevision, McpProxyService, McpProxySummary,
    NetworkPolicy, PrivateDestinationAllowance, ProxyActivity, ProxyApprovalAuthority,
    ProxyApprovalRequest, ProxyDraft, ProxyError, ProxyEventSink, ProxyExposure, ProxyId,
    ProxyLifecycleEvent, ProxyLifecycleState, ProxyLifecycleStore, ProxyRedactionStatus,
    DurableProxyEventSink, ProxyRevisionId, ProxyRevisionStore, ProxyRuntimeProvider, ProxySpec, ProxyStore,
    ProxyStoreBackend, ProxyToolClassification, ProxyTransport, PublishRevision, RetireProxy,
    RollbackProxy, RotateProxyCredentials, RuntimeProfile, SecretRef, TransitionProxyLifecycle,
    DockerCommandRunner, DockerProxyProvider, Readiness, RuntimeCommandOutput,
    RuntimeCommandRunner, RuntimeHandle, ProxyRuntimeReconciler, RuntimeOperations,
    UpdateProxyDraft, UpstreamBinding, bounded_mcp_proxy_service_server,
    parse_proxy_spec_wire_json, validate_mcp_proxy_revision, validate_proxy_spec,
    validate_proxy_spec_wire_json,
};
pub use replay::{
    spawn_fanout_worker, spawn_fanout_worker_with_metrics,
    spawn_fanout_worker_with_metrics_and_shutdown,
};
pub use service::{
    ControlGatewayService, SharedEphemeralStore, bounded_control_gateway_server,
    control_admission_rate_limit_key, control_poll_rate_limit_key,
};
pub use status::{GatewayRuntimeMetrics, GatewayRuntimeSnapshot, GatewayShutdown};

/// Maximum admitted `ControlCommandRequest` size, matching the ingest
/// envelope ceiling (`apex_durability::MAX_ENVELOPE_BYTES`) plus headroom
/// for the outer request framing.
pub const MAX_CONTROL_REQUEST_BYTES: usize = 300 * 1024;

/// Maximum size of the `APEX_CONTROL_AGENT_REVOCATION_FILE`, read in full on
/// every refresh. One line per revoked fingerprint is roughly 65 bytes, so
/// this is generous headroom (a few thousand entries) while still bounding
/// what a mounted file can make this process allocate on a background thread
/// -- the same size class as `MAX_AGENT_TABLE_BYTES` in
/// `startup::service::resolvers`, which this constant lets that module reuse
/// rather than guess a second number that has to be kept in sync by hand.
pub const MAX_AGENT_REVOCATION_FILE_BYTES: usize = 256 * 1024;

pub fn install_rustls_provider() {
    apex_durability::install_rustls_provider();
}
