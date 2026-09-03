//! Phase 0 ingest admission boundary. Transport adapters translate `GatewayError`
//! into tonic status values without exposing caller or payload contents.

pub use apex_contract::proto;
pub use apex_contract::{RedactedProstCodec, RedactedProstDecoder, RedactedProstEncoder};

mod auth;
mod backoff;
mod gateway;
mod http_sinks;
mod idempotency;
mod nats;
mod outbox;
pub mod permissions {
    pub use apex_domain::permissions::private_key_permissions_restricted;
}
mod persistence;
#[cfg(feature = "postgres")]
mod postgres_transport;
mod publisher;
mod security;
mod sinks;
pub mod validation {
    pub use apex_domain::{Caller, IngestRequest, canonical_event_hash};
    pub use apex_domain::{is_lowercase_uuidv7, is_scope_identifier};
}

pub use auth::{
    AuthenticatedGrpcService, BearerTokenResolver, BearerTokenVerifier, CallerVerifier,
    PeerIdentity, bounded_event_ingest_server,
};
pub use apex_auth::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FallbackEphemeralStore,
    FingerprintCounterKey, InMemoryEphemeralStore, RateLimitDecision, RateLimitKey,
};
#[cfg(feature = "valkey")]
pub use apex_auth::{ValkeyConfig, ValkeyEphemeralStore};
pub use apex_domain::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, RedactionSummary,
};
pub use gateway::{
    AuthenticatedIngestAdapter, EventPublisher, IngestGateway, IngestOutcome, PublishOutcome,
    SharedSecurityStore,
};
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
    BacklogObserver, EnqueueResult, EventOutbox, FileOutbox, InMemoryOutbox, OutboxKey,
    OutboxMaintainer, OutboxedPublisher, PendingEventReplayer, SharedOutbox, spawn_fanout_worker,
};
pub use persistence::{FindingJournal, FindingPersistenceError};
#[cfg(feature = "postgres")]
pub use postgres_transport::{apply_postgres_schema, connect_postgres};
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
pub use apex_domain::{Caller, IngestRequest, canonical_event_hash};
pub(crate) use apex_domain::{is_lowercase_uuidv7, is_scope_identifier};

/// Install the explicitly selected ring provider before any TLS client or
/// server is constructed. This keeps reqwest/async-nats on the same provider
/// and avoids pulling a platform-specific native crypto backend into CI or
/// minimal deployment images.
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Maximum admitted serialized event-envelope size: 256 KiB.
pub use apex_domain::MAX_ENVELOPE_BYTES;
pub const MAX_JETSTREAM_SUBJECT_BYTES: usize = 256;
pub const DEFAULT_IDEMPOTENCY_CAPACITY: usize = 50_000;
