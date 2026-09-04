//! Shared durable admission, replay, and downstream fanout primitives.
//!
//! Admission owns only the local durable commit. Downstream publishing stays
//! behind the background fanout worker so callers receive an ACK without
//! waiting for NATS, ClickHouse, or archive availability.

pub use apex_contract::proto;
pub use apex_domain::{
    Caller, DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, IngestRequest, MAX_ENVELOPE_BYTES,
    RedactionSummary, canonical_event_hash,
};
pub use apex_security::{
    ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingError,
    FindingErrorCode, FindingSeverity, FindingStatus, FindingStatusUpdate, FindingStore,
    FindingType, PolicyDecision, SecurityFinding, SecuritySignal, detect_and_record,
    detection_finding,
};

pub mod security {
    pub use apex_security::{
        ContainmentAction, DetectionInput, EvidenceRef, FindingConfidence, FindingError,
        FindingErrorCode, FindingSeverity, FindingStatus, FindingStatusUpdate, FindingStore,
        FindingType, PolicyDecision, SecurityFinding, SecuritySignal, detect_and_record,
        detection_finding,
    };
}

mod backoff;
#[cfg(feature = "postgres")]
mod postgres_client;
#[cfg(feature = "postgres")]
mod postgres_transport;

pub mod permissions {
    pub use apex_domain::permissions::private_key_permissions_restricted;
}

/// What a successful `publish` actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// This call made the event durable.
    Published,
    /// The event was already durable; this call published nothing.
    AlreadyComplete,
}

/// The event-publishing boundary used by admission and replay.
pub trait EventPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError>;

    /// Returns true only when a durable outbox can prove a completed publish
    /// on retry and repair a failed idempotency commit without fanout again.
    fn can_reconcile_commit_failure(&self) -> bool {
        false
    }
}

mod http_sinks;
mod idempotency;
mod nats;
mod outbox;
mod persistence;
mod publisher;
mod sinks;

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
pub use postgres_client::{
    PostgresClientError, PostgresClientOps, PostgresConnection, PostgresTransaction,
};
#[cfg(feature = "postgres")]
pub use postgres_transport::{
    apply_postgres_schema, connect_postgres, connect_postgres_for_worker,
};
pub use publisher::{
    InMemoryPublisher, JetStreamPublisher, JetStreamTransport, RetryingJetStreamTransport,
};
pub use sinks::{
    ArchivePublisher, ClickHousePublisher, DurableEventSink, DurableFanoutPublisher,
    RetryingDurableSink,
};

pub(crate) use apex_domain::{is_lowercase_uuidv7, is_scope_identifier};

/// Install the explicitly selected ring provider before any TLS client or
/// server is constructed.
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const MAX_JETSTREAM_SUBJECT_BYTES: usize = 256;
pub const DEFAULT_IDEMPOTENCY_CAPACITY: usize = 50_000;
