//! gRPC authentication: caller construction, bearer verification, service binding.

mod service;

#[cfg(all(test, feature = "test-support"))]
mod tests;

pub use service::{AuthenticatedGrpcService, bounded_event_ingest_server};
pub use apex_auth::{BearerTokenResolver, BearerTokenVerifier, CallerVerifier, PeerIdentity};
