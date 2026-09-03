//! Admission idempotency: reservation, commit, and in-memory staging store.

mod file;
mod memory;
#[cfg(feature = "postgres")]
mod postgres;
mod types;

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests;
#[cfg(test)]
mod tests;

pub use file::FileIdempotencyStore;
pub use memory::InMemoryIdempotencyStore;
#[cfg(feature = "postgres")]
pub use postgres::PostgresIdempotencyStore;
pub use types::{IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult};
