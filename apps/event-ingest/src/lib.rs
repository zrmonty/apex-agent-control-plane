//! Phase 0 ingest admission boundary. Transport adapters translate `GatewayError`
//! into tonic status values without exposing caller or payload contents.

pub use apex_contract::proto;
pub use apex_contract::{RedactedProstCodec, RedactedProstDecoder, RedactedProstEncoder};

mod auth;
mod gateway;
pub mod http_sinks {
    pub use apex_durability::{
        ArchiveHttpPublisher, AuthenticatedHttpConfig, ClickHouseHttpPublisher,
    };
}
pub mod idempotency {
    #[cfg(feature = "postgres")]
    pub use apex_durability::PostgresIdempotencyStore;
    pub use apex_durability::{
        FileIdempotencyStore, IdempotencyKey, IdempotencyReservation, IdempotencyStore,
        InMemoryIdempotencyStore, ReservationResult,
    };
}
pub mod nats {
    pub use apex_durability::{
        AsyncNatsJetStreamClient, NatsClient, NatsJetStreamTransport, NatsTlsConfig,
    };
}
pub mod outbox {
    #[cfg(feature = "postgres")]
    pub use apex_durability::PostgresOutbox;
    pub use apex_durability::{
        BacklogObserver, EnqueueResult, EventOutbox, FileOutbox, InMemoryOutbox, OutboxKey,
        OutboxMaintainer, OutboxedPublisher, PendingEventReplayer, SharedOutbox,
        spawn_fanout_worker,
    };
}
pub mod permissions {
    pub use apex_domain::permissions::private_key_permissions_restricted;
}
pub mod persistence {
    pub use apex_durability::{FindingJournal, FindingPersistenceError};
}
pub mod publisher {
    pub use apex_durability::{
        InMemoryPublisher, JetStreamPublisher, JetStreamTransport, RetryingJetStreamTransport,
    };
}
pub mod security {
    pub use apex_security::{
        ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingError,
        FindingErrorCode, FindingSeverity, FindingStatus, FindingStatusUpdate, FindingStore,
        FindingType, PolicyDecision, SecurityFinding, SecuritySignal, detect_and_record,
        detection_finding,
    };
}
pub mod sinks {
    pub use apex_durability::{
        ArchivePublisher, ClickHousePublisher, DurableEventSink, DurableFanoutPublisher,
        RetryingDurableSink,
    };
}
pub mod validation {
    pub use apex_domain::{Caller, IngestRequest, canonical_event_hash};
    pub use apex_domain::{is_lowercase_uuidv7, is_scope_identifier};
}

pub use apex_auth::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FallbackEphemeralStore,
    FingerprintCounterKey, InMemoryEphemeralStore, RateLimitDecision, RateLimitKey,
};
#[cfg(feature = "valkey")]
pub use apex_auth::{ValkeyConfig, ValkeyEphemeralStore};
pub(crate) use apex_domain::is_scope_identifier;
pub use apex_domain::{Caller, IngestRequest, canonical_event_hash};
pub use apex_domain::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, RedactionSummary,
};
pub use apex_durability::{
    ArchiveHttpPublisher, ArchivePublisher, AsyncNatsJetStreamClient, AuthenticatedHttpConfig,
    BacklogObserver, ClickHouseHttpPublisher, ClickHousePublisher, DurableEventSink,
    DurableFanoutPublisher, EnqueueResult, EventOutbox, EventPublisher, FileIdempotencyStore,
    FileOutbox, FindingJournal, FindingPersistenceError, IdempotencyKey, IdempotencyReservation,
    IdempotencyStore, InMemoryIdempotencyStore, InMemoryOutbox, InMemoryPublisher,
    JetStreamPublisher, JetStreamTransport, NatsClient, NatsJetStreamTransport, NatsTlsConfig,
    OutboxKey, OutboxMaintainer, OutboxedPublisher, PendingEventReplayer, PublishOutcome,
    ReservationResult, RetryingDurableSink, RetryingJetStreamTransport, SharedOutbox,
    spawn_fanout_worker,
};
#[cfg(feature = "postgres")]
pub use apex_durability::{
    PostgresIdempotencyStore, PostgresOutbox, apply_postgres_schema, connect_postgres,
};
pub use apex_security::{
    ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingError,
    FindingErrorCode, FindingSeverity, FindingStatus, FindingStatusUpdate, FindingStore,
    FindingType, PolicyDecision, SecurityFinding, SecuritySignal, detect_and_record,
};
pub use auth::{
    AuthenticatedGrpcService, BearerTokenResolver, BearerTokenVerifier, CallerVerifier,
    PeerIdentity, bounded_event_ingest_server,
};
pub use gateway::{AuthenticatedIngestAdapter, IngestGateway, IngestOutcome, SharedSecurityStore};
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
