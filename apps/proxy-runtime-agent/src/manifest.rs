//! Typed manifest computation only; never configuration or execution approval.

use crate::{RuntimeError, proto::RuntimeConfiguration};

/// Compute runtime-manifest integrity from this agent's generated ProtoJSON.
/// Only the root selfhash is omitted; control hash and other fields are retained.
///
/// This does not strictly decode external JSON, validate complete config
/// semantics, establish publication, verify an image signature or check a lease.
/// The future caller must bound/decode original input before serialization;
/// this API adds no preallocation/resource boundary for an allocated message.
///
/// # Errors
/// Generated enum drift or encoding failure returns a static redacted refusal,
/// never a panic, sentinel or replacement digest of a default configuration.
pub fn runtime_manifest_hash(configuration: &RuntimeConfiguration) -> Result<String, RuntimeError> {
    apex_domain::runtime_manifest_hash(configuration)
        .map_err(|_| RuntimeError::ManifestEncodingFailed)
}
