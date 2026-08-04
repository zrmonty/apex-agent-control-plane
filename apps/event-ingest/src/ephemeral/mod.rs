//! Optional non-authoritative acceleration boundary (Valkey-ready).
//!
//! Authoritative authorization, audit, cost, and durable events never depend
//! on this store. Cache loss or restart must only degrade aggregation/hints.

mod fallback;
mod memory;
mod types;

#[cfg(feature = "valkey")]
mod valkey;

#[cfg(test)]
mod tests;

pub use fallback::FallbackEphemeralStore;
pub use memory::InMemoryEphemeralStore;
pub use types::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FingerprintCounterKey,
    RateLimitDecision, RateLimitKey,
};

#[cfg(feature = "valkey")]
pub use valkey::{ValkeyConfig, ValkeyEphemeralStore};
