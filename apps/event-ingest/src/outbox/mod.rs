//! Durable event outbox: memory staging, file journal, and live publisher.

mod file;
mod memory;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
mod postgres_replay;
mod publisher;
mod types;

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests;
#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use file::FileOutbox;
pub use memory::InMemoryOutbox;
#[cfg(feature = "postgres")]
pub use postgres::PostgresOutbox;
pub use publisher::{OutboxMaintainer, OutboxedPublisher, PendingEventReplayer};
pub use types::{EnqueueResult, EventOutbox, OutboxKey};
