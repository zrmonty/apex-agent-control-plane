//! Phase 0 ingest admission boundary. Transport adapters translate `GatewayError`
//! into tonic status values without exposing caller or payload contents.

pub mod proto {
    tonic::include_proto!("apex.v1");
}

mod auth;
mod ephemeral;
mod errors;
mod gateway;
mod http_sinks;
mod idempotency;
mod nats;
mod outbox;
pub mod permissions;
mod persistence;
mod publisher;
mod security;
mod sinks;
mod validation;
pub use auth::{
    AuthenticatedGrpcService, BearerTokenResolver, BearerTokenVerifier, CallerVerifier,
    PeerIdentity, bounded_event_ingest_server,
};
pub use ephemeral::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FallbackEphemeralStore,
    FingerprintCounterKey, InMemoryEphemeralStore, RateLimitDecision, RateLimitKey,
};
#[cfg(feature = "valkey")]
pub use ephemeral::{ValkeyConfig, ValkeyEphemeralStore};
pub use errors::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, RedactionSummary,
};
pub use gateway::{AuthenticatedIngestAdapter, EventPublisher, IngestGateway, IngestOutcome};
pub use http_sinks::{ArchiveHttpPublisher, AuthenticatedHttpConfig, ClickHouseHttpPublisher};
#[cfg(feature = "postgres")]
pub use idempotency::PostgresIdempotencyStore;
pub use idempotency::{
    FileIdempotencyStore, IdempotencyKey, IdempotencyReservation, IdempotencyStore,
    InMemoryIdempotencyStore, ReservationResult,
};
pub use nats::{AsyncNatsJetStreamClient, NatsClient, NatsJetStreamTransport, NatsTlsConfig};
#[cfg(feature = "postgres")]
pub use outbox::PostgresOutbox;
pub use outbox::{
    EnqueueResult, EventOutbox, FileOutbox, InMemoryOutbox, OutboxKey, OutboxedPublisher,
    PendingEventReplayer,
};
pub use persistence::{FindingJournal, FindingPersistenceError};
pub use publisher::{
    InMemoryPublisher, JetStreamPublisher, JetStreamTransport, RetryingJetStreamTransport,
};
pub use security::{
    ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingError,
    FindingErrorCode, FindingSeverity, FindingStatus, FindingStatusUpdate, FindingStore,
    FindingType, PolicyDecision, SecurityFinding, SecuritySignal, detect_and_record,
};
pub use sinks::{
    ArchivePublisher, ClickHousePublisher, DurableEventSink, DurableFanoutPublisher,
    RetryingDurableSink,
};
pub use validation::{Caller, IngestRequest};
pub(crate) use validation::{is_lowercase_uuidv7, is_scope_identifier};

/// Maximum admitted serialized event-envelope size: 256 KiB.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
pub const MAX_JETSTREAM_SUBJECT_BYTES: usize = 256;
pub const DEFAULT_IDEMPOTENCY_CAPACITY: usize = 50_000;
