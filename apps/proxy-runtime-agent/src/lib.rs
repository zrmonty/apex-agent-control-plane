//! Runtime wire/inspection, current-operation client and image catalog boundary.
//!
//! The mTLS authority client returns a point-in-time snapshot, not an execution
//! permit. There is no production listener, engine call, secret staging or
//! admission here. Catalog selection does not verify image signatures. These
//! independent gates must be settled before any future Ensure side effect.

pub mod authority;
mod error;
pub mod image_catalog;
mod inspect;
mod inspect_decode;
mod manifest;
mod shapes;
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
