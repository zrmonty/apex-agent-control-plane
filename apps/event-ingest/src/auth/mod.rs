//! gRPC authentication: caller construction, bearer verification, service binding.

mod service;
mod verifier;

#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use service::{AuthenticatedGrpcService, bounded_event_ingest_server};
pub use verifier::{BearerTokenResolver, BearerTokenVerifier, CallerVerifier, PeerIdentity};
