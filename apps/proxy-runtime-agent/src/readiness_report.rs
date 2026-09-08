//! Bounded health stdout decoding; data validation alone grants no authority.

use crate::proto;
use std::fmt;

mod sample;
mod validation;
mod wire;
pub use sample::{HealthSample, decode_health_sample_stdout};

/// Static refusal that never retains input or parser diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessReportError;

impl fmt::Display for ReadinessReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("readiness report rejected")
    }
}
impl std::error::Error for ReadinessReportError {}

/// Validated ready data, never a freshness, execution or serving permit.
/// Debug deliberately excludes all supplied values.
pub struct HealthReport(proto::ReadinessReport);

impl HealthReport {
    /// Exact decoded values, retaining the original target and optional integers.
    pub fn as_report(&self) -> &proto::ReadinessReport {
        &self.0
    }
}

impl fmt::Debug for HealthReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HealthReport { [redacted; data only] }")
    }
}

/// Decode the legacy plain-report line against its original launch binding.
/// The fixed executable now emits a versioned sample; use
/// [`decode_health_sample_stdout`] for that output.
///
/// The caller owns launch provenance, currentness and authenticated execution.
/// Expected launch metadata is shape-checked; digests are compared, not recomputed.
/// Success is data only: bound the actual observation, then recheck installation,
/// journal/metadata, physical execution and the original deadline before routing.
/// Never substitute a current operation fence for the original launch target.
/// No wall-time freshness or serving authority is inferred here.
///
/// # Errors
/// Refuses invalid expected bindings, malformed or oversized framing/JSON,
/// mismatched identities, incomplete readiness and malformed stage timings.
pub fn decode_health_stdout(
    stdout: &[u8],
    expected: &proto::RuntimeLaunchContext,
) -> Result<HealthReport, ReadinessReportError> {
    let payload = framed_payload(stdout, 8193)?;
    validation::expected_binding(expected)?;
    // No Value intermediate: derive sees every original decoded key, including
    // duplicates and escaped aliases. Object wrappers reject positional arrays.
    let wire::Object(report): wire::Object<wire::Report> =
        serde_json::from_slice(payload).map_err(|_| ReadinessReportError)?;
    validation::report(report.into_proto(), expected).map(HealthReport)
}

fn framed_payload(stdout: &[u8], maximum: usize) -> Result<&[u8], ReadinessReportError> {
    // Bound original bytes before parsing/allocation. Both profiles are exactly
    // one object followed by LF; neither permits surrounding whitespace.
    if !(3..=maximum).contains(&stdout.len()) || stdout.last() != Some(&b'\n') {
        return Err(ReadinessReportError);
    }
    let payload = &stdout[..stdout.len() - 1];
    if payload.first() != Some(&b'{')
        || payload.last() != Some(&b'}')
        || payload.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(ReadinessReportError);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests;
