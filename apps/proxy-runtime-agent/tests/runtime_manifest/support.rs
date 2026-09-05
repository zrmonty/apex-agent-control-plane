//! Read-only, bounded known-producer test fixture; never a production decoder.

use std::{fs::File, io::Read, path::PathBuf};

use apex_proxy_runtime_agent::proto::RuntimeConfiguration;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const ARTIFACT_SHA: &str = "970cfd7a059a4761fc8b4ad6f8f9d5dd4f4f4f4c4f2d16995cde807d20fdd554";
pub const MANIFEST: &str = "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da";
pub const BIG: u64 = 9_007_199_254_740_993;
pub const CANARY: &str = "PRIVATE_AGENT_MANIFEST_CANARY_7C";
const MAX_FIXTURE_BYTES: u64 = 65_536;

pub struct Fixture {
    pub body: Value,
    pub configuration: RuntimeConfiguration,
}

pub fn actual_fixture() -> Result<Fixture, &'static str> {
    let path = std::env::var_os("APEX_RUNTIME_FIXTURE_PATH")
        .filter(|value| !value.is_empty())
        .ok_or("APEX_RUNTIME_FIXTURE_PATH is required: supply the actual Rust exporter artifact")?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("APEX_RUNTIME_FIXTURE_PATH must be an absolute existing artifact path");
    }
    let file = File::open(path).map_err(|_| "actual Rust exporter artifact cannot be opened")?;
    let metadata = file
        .metadata()
        .map_err(|_| "actual artifact metadata unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_FIXTURE_BYTES {
        return Err("actual exporter artifact must be a regular file within the test byte limit");
    }
    let mut bytes = Vec::new();
    file.take(MAX_FIXTURE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "actual exporter artifact read failed")?;
    if bytes.len() > MAX_FIXTURE_BYTES as usize {
        return Err("actual exporter artifact exceeds the test byte limit");
    }
    if format!("{:x}", Sha256::digest(&bytes)) != ARTIFACT_SHA {
        return Err(
            "actual exporter artifact SHA256 differs from the independently pinned fixture",
        );
    }
    let body = serde_json::from_slice(&bytes).map_err(|_| "known producer JSON is malformed")?;
    // Own generated Rust types. This known-artifact test is NOT a claim that
    // pbjson is the complete strict external JSON/config admission boundary.
    let configuration = serde_json::from_slice(&bytes)
        .map_err(|_| "known producer body differs from the agent's generated contract")?;
    Ok(Fixture {
        body,
        configuration,
    })
}
