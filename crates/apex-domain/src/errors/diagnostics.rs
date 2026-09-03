use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::code::GatewayErrorCode;

static REPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticScope {
    pub workspace_id: String,
    pub namespace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCorrelation {
    pub event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticFailure {
    pub code: GatewayErrorCode,
    pub category: &'static str,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticEvidence {
    pub component: String,
    pub stage: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSummary {
    pub omitted_fields: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDiagnosticReport {
    pub report_id: String,
    pub fingerprint: String,
    pub severity: &'static str,
    pub status: &'static str,
    pub scope: DiagnosticScope,
    pub correlation: DiagnosticCorrelation,
    pub failure: DiagnosticFailure,
    pub summary: &'static str,
    pub cause: &'static str,
    pub causal_chain: Vec<&'static str>,
    pub evidence: DiagnosticEvidence,
    pub redaction_summary: RedactionSummary,
    pub recommended_next_steps: &'static [&'static str],
}

impl GatewayDiagnosticReport {
    /// Safe, text-only handoff for an authorized troubleshooting workflow or coding agent.
    pub fn to_ai_markdown(&self) -> String {
        // Fields are public for transport serialization. Re-check them here so a
        // post-construction mutation cannot bypass the AI-handoff boundary.
        let report_id = safe_diagnostic_identifier(self.report_id.clone());
        let fingerprint = safe_diagnostic_identifier(self.fingerprint.clone());
        let workspace_id = safe_diagnostic_identifier(self.scope.workspace_id.clone());
        let namespace_id = safe_diagnostic_identifier(self.scope.namespace_id.clone());
        let component = safe_diagnostic_identifier(self.evidence.component.clone());
        let event_id = self
            .correlation
            .event_id
            .as_deref()
            .map(|value| safe_diagnostic_identifier(value.to_owned()))
            .unwrap_or_else(|| "not retained".to_owned());
        let next_steps = self
            .recommended_next_steps
            .iter()
            .map(|step| format!("- {step}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "# Apex Ingest Diagnostic\n\n## Failure\n- Report ID: `{}`\n- Fingerprint: `{}`\n- Code: `{}`\n- Category: `{}`\n- Retryable: `{}`\n\n## Summary\n{}\n\n## Scope and correlation\n- workspace_id: `{}`\n- namespace_id: `{}`\n- event_id: {}\n\n## Cause\n{}\n\n## Causal evidence\n- component: `{}`\n- stage: `{}`\n- chain: `{}`\n\n## Recommended next steps\n{}\n\n## Redaction\nRaw event payloads, caller identity, and raw transport errors are intentionally omitted.\n",
            report_id,
            fingerprint,
            self.failure.code.public_code(),
            self.failure.category,
            self.failure.retryable,
            self.summary,
            workspace_id,
            namespace_id,
            event_id,
            self.cause,
            component,
            self.evidence.stage,
            self.causal_chain.join(" -> "),
            next_steps,
        )
    }
}

pub(crate) fn safe_diagnostic_identifier(value: String) -> String {
    let is_safe = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'));
    if is_safe {
        value
    } else {
        "[redacted invalid identifier]".to_owned()
    }
}

pub(crate) fn uuid7_report_id() -> String {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let sequence =
        REPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let bytes = [
        (timestamp_ms >> 40) as u8,
        (timestamp_ms >> 32) as u8,
        (timestamp_ms >> 24) as u8,
        (timestamp_ms >> 16) as u8,
        (timestamp_ms >> 8) as u8,
        timestamp_ms as u8,
        0x70 | ((sequence >> 56) as u8 & 0x0f),
        (sequence >> 48) as u8,
        0x80 | ((sequence >> 40) as u8 & 0x3f),
        (sequence >> 32) as u8,
        (sequence >> 24) as u8,
        (sequence >> 16) as u8,
        (sequence >> 8) as u8,
        sequence as u8,
        (sequence.rotate_left(17) >> 8) as u8,
        sequence.rotate_left(29) as u8,
    ];
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}


