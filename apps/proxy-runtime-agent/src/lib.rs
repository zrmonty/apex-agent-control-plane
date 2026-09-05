//! Pure runtime wire/inspection boundary, not a provisioning agent.
//!
//! No listener, engine call, secret resolution, persistence or admission exists
//! here. Relation checks do not establish published-config integrity, approved
//! executable/image/signature policy, authenticated ownership or a current lease.
//! Those independent gates must be settled before any future Ensure side effect.

mod error;
mod inspect;
mod inspect_decode;
mod shapes;
mod target;

pub use error::RuntimeError;
pub use inspect::{
    EngineState, ExpectedRuntimeOwnership, InspectedRuntime, RuntimeOwnershipInput,
    check_owned_inspect, parse_inspect_id,
};
pub use target::{check_runtime_target, check_target_configuration_binding};

/// Untrusted wire messages generated from the canonical runtime protos/imports.
/// Generated RPC types alone do not create a server or authenticate a caller.
pub mod proto {
    tonic::include_proto!("apex.v1");
    include!(concat!(env!("OUT_DIR"), "/apex.v1.serde.rs"));
}

/// Canonical descriptor evidence for wire-compatibility tests; not runtime policy.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/apex-runtime-agent.binpb"));
