//! Runtime-manifest integrity primitive, separate from event canonicalization.
//!
//! Typed application wrappers supply already-decoded generated Serialize data.
//! This is not an external JSON decoder, complete configuration validator,
//! publication check, signature verifier or execution-authority capability.
//! Callers must bound/decode original inputs before invoking serialization;
//! this extraction adds no preallocation or input-resource boundary.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Static encoding refusal with no input, serializer cause or source chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeManifestEncodingError;

impl std::fmt::Display for RuntimeManifestEncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Runtime manifest cannot be encoded.")
    }
}

impl std::error::Error for RuntimeManifestEncodingError {}

/// Compute the v1 runtime digest from generated ProtoJSON: recursively sort
/// object keys, preserve arrays/schema-body strings, omit only root selfhash.
/// The control configHash and all other generated fields remain in the digest.
///
/// # Errors
/// Refuse serialization failure or a nonobject encoding with a static error.
pub fn runtime_manifest_hash<T: Serialize + ?Sized>(
    configuration: &T,
) -> Result<String, RuntimeManifestEncodingError> {
    let mut json = serde_json::to_value(configuration).map_err(|_| RuntimeManifestEncodingError)?;
    let object = json.as_object_mut().ok_or(RuntimeManifestEncodingError)?;
    object.remove("runtimeManifestHash");
    let canonical = serde_json::to_vec(&sorted(json)).map_err(|_| RuntimeManifestEncodingError)?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut fields: Vec<_> = fields.into_iter().collect();
            fields.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            Value::Object(
                fields
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests;
