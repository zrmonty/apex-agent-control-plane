//! Phase 0.5 out-of-band (OOB) control command gateway.
//!
//! Independently authenticated from the `event-ingest` data path (see
//! [`auth`]), this crate exposes the five cooperative v1 controls --
//! `stop`/`pause`/`resume`/`inject`/`set_budget` (ADR-0005) -- behind a
//! durable command outbox (ADR-0006). Every accepted command is validated
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

mod auth;
mod envelope;
mod errors;
mod outbox;
mod replay;
mod service;

pub use auth::{
    OperatorCaller, OperatorCredentialResolver, OperatorTokenAuthenticator,
    OperatorTokenTableError, StaticOperatorTokenResolver, parse_operator_token_table,
};
pub use envelope::{ControlCommandInput, build_control_request};
pub use errors::CommandError;
pub use outbox::{ControlOutboxBackend, submit_command};
pub use replay::spawn_fanout_worker;
pub use service::{ControlGatewayService, bounded_control_gateway_server};

/// Maximum admitted `ControlCommandRequest` size, matching the ingest
/// envelope ceiling (`apex_event_ingest::MAX_ENVELOPE_BYTES`) plus headroom
/// for the outer request framing.
pub const MAX_CONTROL_REQUEST_BYTES: usize = 300 * 1024;

pub fn install_rustls_provider() {
    apex_event_ingest::install_rustls_provider();
}
