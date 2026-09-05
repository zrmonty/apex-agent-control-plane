//! Same-origin browser edge. Operator credentials stay on the server; the
//! existing tonic handlers remain the management authorization authority.

pub mod bundle;
pub mod crypto;
pub mod errors;
pub mod oidc;
pub mod rpc;
pub mod security;
pub mod sessions;
pub mod edge;
pub mod callback;
pub mod telemetry;
