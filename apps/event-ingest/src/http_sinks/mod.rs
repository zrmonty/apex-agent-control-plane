//! Authenticated HTTPS ClickHouse and archive projection clients.

mod config;
mod event;
mod publishers;
mod secrets;

#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use config::AuthenticatedHttpConfig;
pub use publishers::{ArchiveHttpPublisher, ClickHouseHttpPublisher};
