//! Runtime wire/inspection, authority client and provisioning prerequisites.
//!
//! The mTLS authority client returns a point-in-time snapshot, not an execution
//! permit. Linux signature verification and confined secret staging are separate
//! synchronous boundaries. There is no production listener, engine call or
//! admission here. Online resolution binds RuntimeConfiguration to publication;
//! launch-context/material binding and owned effect composition must still be
//! settled before any future Ensure side effect.

pub mod authority;
#[cfg(target_os = "linux")]
mod command;
mod error;
pub mod image_catalog;
mod inspect;
mod inspect_decode;
mod manifest;
pub mod secrets;
mod shapes;
pub mod signature;
mod target;

pub use error::RuntimeError;
pub use inspect::{
    EngineState, ExpectedRuntimeOwnership, InspectedRuntime, RuntimeOwnershipInput,
    check_owned_inspect, parse_inspect_id,
};
pub use manifest::runtime_manifest_hash;
pub use target::{check_runtime_target, check_target_configuration_binding};

/// Untrusted wire messages generated from the canonical runtime protos/imports.
/// Generated RPC types alone do not create a server or authenticate a caller.
#[allow(
    unknown_lints,
    clippy::useless_borrows_in_formatting,
    reason = "pbjson-build 0.9 emits &FIELDS; this generated-code lint is unknown before Rust 1.97"
)]
pub mod proto {
    tonic::include_proto!("apex.v1");
    include!(concat!(env!("OUT_DIR"), "/apex.v1.serde.rs"));
}

/// Canonical descriptor evidence for wire-compatibility tests; not runtime policy.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/apex-runtime-agent.binpb"));
