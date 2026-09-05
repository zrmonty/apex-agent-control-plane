//! Shared authentication and non-authoritative ephemeral acceleration.
//!
//! Transport-agnostic credential verification lives here. The event-ingest
//! application retains its gRPC service adapter because that adapter also
//! owns admission, durable outbox, and security-signal orchestration.

mod ephemeral;
mod runtime_peer;
mod verifier;

pub use apex_domain::{Caller, GatewayError, GatewayErrorCode, is_scope_identifier};
pub use ephemeral::{
    DenyHintKey, EphemeralError, EphemeralErrorCode, EphemeralStore, FallbackEphemeralStore,
    FingerprintCounterKey, InMemoryEphemeralStore, RateLimitDecision, RateLimitKey,
};
#[cfg(feature = "valkey")]
pub use ephemeral::{ValkeyConfig, ValkeyEphemeralStore};
pub use runtime_peer::{
    AuthenticatedRuntimePeer, RuntimePeerError, RuntimePeerPair, RuntimePeerPolicy, RuntimePeerRole,
};
pub use verifier::{BearerTokenResolver, BearerTokenVerifier, CallerVerifier, PeerIdentity};
