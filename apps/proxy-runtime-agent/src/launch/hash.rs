//! Generated ProtoJSON canonicalization, separate from runtime manifest hashing.

use super::LaunchError;
use crate::proto::RuntimeLaunchContext;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(super) fn launch_hash(context: &RuntimeLaunchContext) -> Result<String, LaunchError> {
    let bytes = bounded_json(context, 16_384)?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| LaunchError::Encoding)?;
    value
        .as_object_mut()
        .ok_or(LaunchError::Encoding)?
        .remove("launchContextHash");
    let canonical = bounded_json(&sorted(value), 16_384)?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut fields: Vec<_> = fields.into_iter().collect();
            fields.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            Value::Object(fields.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

pub(super) fn bounded_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, LaunchError> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::other("launch encoding bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| LaunchError::Encoding)?;
    Ok(output.bytes)
}
