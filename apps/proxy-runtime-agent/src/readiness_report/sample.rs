use super::{HealthReport, ReadinessReportError, framed_payload, validation, wire};
use crate::proto;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::fmt;

/// Validated process-output data, not physical termination or serving authority.
pub struct HealthSample {
    report: HealthReport,
    valid_for_ns: u64,
}
impl HealthSample {
    /// Original report, including all integer timestamps and uncertainty.
    pub fn report(&self) -> &proto::ReadinessReport {
        self.report.as_report()
    }
    /// Remaining duration advertised before output, never a new interval on receipt.
    pub fn valid_for_ns(&self) -> u64 {
        self.valid_for_ns
    }
}
impl fmt::Debug for HealthSample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HealthSample { [redacted; data only] }")
    }
}

/// Decode one bounded sample line against the original installed launch.
///
/// The receiver must anchor the interval before dispatch of the exact process,
/// require its successful physical termination and preserve elapsed time through
/// subsequent authenticated forwarding. This parser grants no freshness authority.
///
/// # Errors
/// Refuses malformed framing, invalid duration, or invalid/mismatched readiness.
pub fn decode_health_sample_stdout(
    stdout: &[u8],
    expected: &proto::RuntimeLaunchContext,
) -> Result<HealthSample, ReadinessReportError> {
    let payload = framed_payload(stdout, 16385)?;
    validation::expected_binding(expected)?;
    let wire::Object(sample): wire::Object<Sample> =
        serde_json::from_slice(payload).map_err(|_| ReadinessReportError)?;
    if sample.schema_version != 1 || !(1..=10_000_000_000).contains(&sample.valid_for_ns.0) {
        return Err(ReadinessReportError);
    }
    // Borrow the original JSON span: whitespace and escapes count toward the
    // report's independent ceiling, before any typed report decoding/allocation.
    let report_json = sample.report.get();
    if report_json.len() > 8192 {
        return Err(ReadinessReportError);
    }
    // Decode the same bytes so duplicate/escaped keys and nulls remain visible.
    let wire::Object(report): wire::Object<wire::Report> =
        serde_json::from_str(report_json).map_err(|_| ReadinessReportError)?;
    let report = validation::report(report.into_proto(), expected)?;
    Ok(HealthSample {
        report: HealthReport(report),
        valid_for_ns: sample.valid_for_ns.0,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sample<'a> {
    schema_version: u32,
    #[serde(borrow)]
    report: &'a RawValue,
    valid_for_ns: wire::Uint,
}
