#![cfg(all(feature = "postgres", target_os = "linux"))]
//! Actual separately compiled CP and agent, PostgreSQL, mTLS, Cosign and Docker.
#[path = "proxy_runtime_execution/fixture.rs"]
mod fixture;
#[path = "proxy_runtime_execution/journey.rs"]
mod journey;
#[path = "proxy_runtime_execution/metadata.rs"]
mod metadata;
#[allow(dead_code)]
#[path = "../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
#[path = "proxy_runtime_execution/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "proxy_operation_recovery/support.rs"]
mod recovery;
#[path = "proxy_runtime_execution/registration.rs"]
mod registration;
#[path = "proxy_runtime_operation/spec.rs"]
mod spec;
