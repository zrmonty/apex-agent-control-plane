//! Ingest admission gateway: validation handoff, identity checks, idempotency.

mod adapter;
mod core;
mod publisher;

#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use adapter::AuthenticatedIngestAdapter;
pub use core::IngestGateway;
pub use publisher::{EventPublisher, PublishOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Accepted,
    Duplicate,
}
