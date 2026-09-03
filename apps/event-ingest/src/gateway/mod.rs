//! Ingest admission gateway: validation handoff, identity checks, idempotency.

mod adapter;
mod core;

#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use adapter::AuthenticatedIngestAdapter;
#[allow(unused_imports)]
pub use apex_durability::{EventPublisher, PublishOutcome};
pub use core::{IngestGateway, SharedSecurityStore};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Accepted,
    Duplicate,
}
