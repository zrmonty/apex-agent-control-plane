#![cfg(feature = "postgres")]
//! Required real PostgreSQL and actual TLS tests, not production startup proof.
#[path = "proxy_runtime_authority/blocked_policy.rs"]
mod blocked_policy;
#[path = "proxy_runtime_authority/callback.rs"]
mod callback;
#[path = "proxy_runtime_authority/concurrency.rs"]
mod concurrency;
#[path = "proxy_runtime_authority/material.rs"]
mod material;
#[path = "proxy_runtime_authority/observer.rs"]
mod observer;
#[allow(dead_code)]
#[path = "proxy_runtime_operation/support.rs"]
mod operation;
#[path = "proxy_runtime_authority/ownership.rs"]
mod ownership;
#[allow(dead_code)]
#[path = "../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
#[allow(dead_code)]
#[path = "proxy_operation_recovery/support.rs"]
mod recovery;
#[path = "proxy_runtime_authority/refresh.rs"]
mod refresh;
#[path = "proxy_runtime_authority/transport.rs"]
mod transport;
