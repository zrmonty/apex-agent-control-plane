#![cfg(feature = "postgres")]
// Required real PostgreSQL suite; a missing dedicated fixture is a setup failure.
// The shared recovery fixture owns only a generated schema, never the root DB.
#[path = "proxy_runtime_operation/claims.rs"]
mod claims;
#[path = "proxy_runtime_operation/concurrency.rs"]
mod concurrency;
#[path = "proxy_runtime_operation/integrity.rs"]
mod integrity;
#[path = "proxy_runtime_operation/lifecycle.rs"]
mod lifecycle;
#[path = "proxy_operation_recovery/support.rs"]
mod recovery;
#[path = "proxy_runtime_operation/support.rs"]
mod support;
