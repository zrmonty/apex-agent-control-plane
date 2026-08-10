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
//! (`apex_event_ingest::IngestRequest::from_validated_transport`), then
//! durably enqueued so it survives a crash before fanout, and later flows
//! into the same queryable trace as everything else.
//!
//! Durability does not have a hard dependency on JetStream/ClickHouse being
//! reachable: a command is durably accepted once the outbox commits the row,
//! before any downstream fanout is attempted. See [`replay`].

pub mod proto {
    tonic::include_proto!("apex.v1");
}

mod agent_auth;
mod auth;
mod envelope;
mod errors;
mod inbox;
mod keycloak;
mod outbox;
mod replay;
mod service;
mod status;

pub use agent_auth::{
    AgentTokenTableError, AgentWorkloadAuthenticator, BoxedAgentWorkloadResolver,
    StaticAgentWorkloadResolver, agent_workload_subject, parse_agent_token_table,
    peer_identity_from_request,
};
pub use auth::{
    BoxedOperatorCredentialResolver, OperatorCaller, OperatorCredentialResolver,
    OperatorTokenAuthenticator, OperatorTokenTableError, StaticOperatorTokenResolver,
    parse_operator_token_table,
};
pub use envelope::{
    AcceptedCommand, ControlCommandInput, build_control_request,
    pending_command_from_ingest_request,
};
pub use errors::{CommandError, CommandErrorCode};
pub use inbox::{
    AckResult, CommandInbox, ControlInboxBackend, DEFAULT_INBOX_CAPACITY,
    DEFAULT_MAX_COMMANDS_PER_POLL, DEFAULT_MAX_DELIVERY_ATTEMPTS, DEFAULT_REDELIVERY_AFTER,
    DeliveryPolicy, DeliveryStatus, ExactScope, FileCommandInbox, InMemoryCommandInbox, InboxKey,
    MAX_COMMANDS_PER_POLL, PendingCommand, PollTarget, RecordResult, ScopeAuthorizer,
};
#[cfg(feature = "postgres")]
pub use inbox::{PostgresCommandInbox, RecoveringPostgresCommandInbox};
pub use keycloak::{
    KeycloakConfig, KeycloakConfigError, KeycloakOperatorCredentialResolver, KeycloakRejection,
};
#[cfg(feature = "postgres")]
pub use outbox::RecoveringPostgresOutbox;
pub use outbox::{ControlOutboxBackend, submit_command};
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
/// envelope ceiling (`apex_event_ingest::MAX_ENVELOPE_BYTES`) plus headroom
/// for the outer request framing.
pub const MAX_CONTROL_REQUEST_BYTES: usize = 300 * 1024;

pub fn install_rustls_provider() {
    apex_event_ingest::install_rustls_provider();
}
