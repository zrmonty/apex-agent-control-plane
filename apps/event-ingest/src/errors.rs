use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::is_lowercase_uuidv7;

static REPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayErrorCode {
    Unauthenticated,
    InvalidAuthorization,
    ScopeDenied,
    InvalidEventId,
    InvalidEnvelope,
    InvalidStructure,
    InvalidTimestamp,
    InvalidIntegrity,
    PayloadTooLarge,
    IdempotencyCapacity,
    PublishFailed,
    Internal,
    SubjectTooLong,
    InvalidRetryConfiguration,
    InvalidNatsConfiguration,
    InvalidNatsPublishRequest,
    NatsConnectionFailed,
    IdempotencyConflict,
    InvalidSinkConfiguration,
}

impl GatewayErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::InvalidAuthorization => "INVALID_AUTHORIZATION_METADATA",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::InvalidEventId => "INVALID_EVENT_ID",
            Self::InvalidEnvelope => "INVALID_ENVELOPE",
            Self::InvalidStructure => "INVALID_ENVELOPE_STRUCTURE",
            Self::InvalidTimestamp => "INVALID_TIMESTAMP",
            Self::InvalidIntegrity => "INVALID_INTEGRITY",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::IdempotencyCapacity => "IDEMPOTENCY_CAPACITY",
            Self::PublishFailed => "PUBLISH_FAILED",
            Self::Internal => "INTERNAL_FAILURE",
            Self::SubjectTooLong => "JETSTREAM_SUBJECT_TOO_LONG",
            Self::InvalidRetryConfiguration => "INVALID_RETRY_CONFIGURATION",
            Self::InvalidNatsConfiguration => "INVALID_NATS_CONFIGURATION",
            Self::InvalidNatsPublishRequest => "INVALID_NATS_PUBLISH_REQUEST",
            Self::NatsConnectionFailed => "NATS_CONNECTION_FAILED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::InvalidSinkConfiguration => "INVALID_SINK_CONFIGURATION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError {
    pub code: GatewayErrorCode,
    pub summary: &'static str,
    pub cause: &'static str,
    pub retryable: bool,
    pub recommended_next_steps: &'static [&'static str],
}

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
            self.failure.code.as_str(),
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

impl GatewayError {
    pub fn unauthenticated() -> Self {
        Self::new(GatewayErrorCode::Unauthenticated)
    }

    pub fn invalid_authorization() -> Self {
        Self::new(GatewayErrorCode::InvalidAuthorization)
    }

    pub fn scope_denied() -> Self {
        Self::new(GatewayErrorCode::ScopeDenied)
    }

    pub fn publish_failed() -> Self {
        Self::new(GatewayErrorCode::PublishFailed)
    }

    pub fn internal() -> Self {
        Self::new(GatewayErrorCode::Internal)
    }

    pub fn subject_too_long() -> Self {
        Self::new(GatewayErrorCode::SubjectTooLong)
    }

    pub fn invalid_retry_configuration() -> Self {
        Self::new(GatewayErrorCode::InvalidRetryConfiguration)
    }

    pub fn invalid_nats_configuration() -> Self {
        Self::new(GatewayErrorCode::InvalidNatsConfiguration)
    }

    pub fn invalid_nats_publish_request() -> Self {
        Self::new(GatewayErrorCode::InvalidNatsPublishRequest)
    }

    pub fn nats_connection_failed() -> Self {
        Self::new(GatewayErrorCode::NatsConnectionFailed)
    }

    pub fn invalid_sink_configuration() -> Self {
        Self::new(GatewayErrorCode::InvalidSinkConfiguration)
    }

    pub fn idempotency_conflict() -> Self {
        Self::new(GatewayErrorCode::IdempotencyConflict)
    }

    pub(crate) fn new(code: GatewayErrorCode) -> Self {
        match code {
            GatewayErrorCode::Unauthenticated => Self {
                code,
                summary: "Ingest rejected an unauthenticated caller.",
                cause: "No verified workload identity was supplied to the ingest boundary.",
                retryable: false,
                recommended_next_steps: &[
                    "Provide a valid workload identity or bearer token.",
                    "Confirm the ingest endpoint trusts the configured identity issuer.",
                ],
            },
            GatewayErrorCode::InvalidAuthorization => Self {
                code,
                summary: "Ingest rejected malformed or ambiguous authorization metadata.",
                cause: "The authorization header was not exactly one valid Bearer credential, or its metadata encoding was invalid.",
                retryable: false,
                recommended_next_steps: &[
                    "Send exactly one ASCII authorization header using the form Bearer <token>.",
                    "Remove duplicate authorization headers and do not include whitespace inside the token.",
                ],
            },
            GatewayErrorCode::ScopeDenied => Self {
                code,
                summary: "Ingest denied the caller's requested workspace and namespace.",
                cause: "The verified identity does not have permission for the event scope.",
                retryable: false,
                recommended_next_steps: &[
                    "Grant the workload identity ingest permission for the target scope.",
                    "Confirm the event workspace_id and namespace_id are correct.",
                ],
            },
            GatewayErrorCode::InvalidEventId => Self {
                code,
                summary: "Ingest requires a lowercase UUIDv7 event_id.",
                cause: "The idempotency key did not meet the Apex UUIDv7 contract.",
                retryable: false,
                recommended_next_steps: &[
                    "Generate a lowercase UUIDv7 before emitting the event.",
                    "Reuse the same event_id only when retrying that exact event.",
                ],
            },
            GatewayErrorCode::InvalidEnvelope => Self {
                code,
                summary: "Ingest rejected an empty event envelope.",
                cause: "The transport supplied no serialized event bytes for admission.",
                retryable: false,
                recommended_next_steps: &[
                    "Serialize a complete Apex v1 event envelope before sending it.",
                    "Validate the envelope locally before retrying with the same event_id.",
                ],
            },
            GatewayErrorCode::InvalidStructure => Self {
                code,
                summary: "Ingest rejected an event with missing or unsupported required fields.",
                cause: "The decoded Protobuf envelope did not contain the required v1 scope, actor, version, data, or schema fields.",
                retryable: false,
                recommended_next_steps: &[
                    "Populate every required Apex v1 envelope message and field.",
                    "Validate the decoded envelope against the Protobuf and JSON Schema contracts before retrying.",
                ],
            },
            GatewayErrorCode::InvalidTimestamp => Self {
                code,
                summary: "Ingest rejected an event with an invalid UTC timestamp.",
                cause: "The timestamp was not a valid RFC 3339 UTC value with the required microsecond precision.",
                retryable: false,
                recommended_next_steps: &[
                    "Emit a UTC timestamp in YYYY-MM-DDTHH:MM:SS.ffffffZ form.",
                    "Check the producer clock and timestamp formatter before retrying.",
                ],
            },
            GatewayErrorCode::InvalidIntegrity => Self {
                code,
                summary: "Ingest rejected an event with invalid integrity metadata.",
                cause: "The event hash or previous hash was not lowercase SHA-256 hex in the required v1 shape.",
                retryable: false,
                recommended_next_steps: &[
                    "Recompute event_hash from the RFC 8785 canonical unsigned envelope.",
                    "Set prev_hash to the prior run hash or null at the chain root.",
                ],
            },
            GatewayErrorCode::PayloadTooLarge => Self {
                code,
                summary: "Ingest rejected an event envelope larger than the configured limit.",
                cause: "The serialized event exceeded the 256 KiB admission limit.",
                retryable: false,
                recommended_next_steps: &[
                    "Truncate approved display fields before emission.",
                    "Keep the serialized envelope at or below 256 KiB.",
                ],
            },
            GatewayErrorCode::IdempotencyCapacity => Self {
                code,
                summary: "Ingest cannot safely accept new events because idempotency capacity is exhausted.",
                cause: "The in-memory idempotency boundary reached its configured limit and will not evict keys.",
                retryable: true,
                recommended_next_steps: &[
                    "Restore or configure the durable idempotency store.",
                    "Retry the same event_id only after capacity is available.",
                ],
            },
            GatewayErrorCode::PublishFailed => Self {
                code,
                summary: "Ingest could not publish the admitted event to a durable destination.",
                cause: "The configured publisher or downstream durable sink did not acknowledge the event within its bounded request policy, so the event was not marked accepted.",
                retryable: true,
                recommended_next_steps: &[
                    "Check the configured JetStream, ClickHouse, or archive destination health and mTLS connectivity without logging credentials.",
                    "Retry using the same event_id after the durable destination recovers.",
                ],
            },
            GatewayErrorCode::Internal => Self {
                code,
                summary: "Ingest encountered an internal service failure.",
                cause: "A protected ingest component terminated unexpectedly before completing admission.",
                retryable: true,
                recommended_next_steps: &[
                    "Check the ingest service health and diagnostic logs using the report correlation ID.",
                    "Retry the same event_id after the service is healthy.",
                ],
            },
            GatewayErrorCode::SubjectTooLong => Self {
                code,
                summary: "Ingest could not derive a valid JetStream subject for the event scope.",
                cause: "The workspace and namespace identifiers exceed the configured broker subject-length limit when combined.",
                retryable: false,
                recommended_next_steps: &[
                    "Use shorter workspace_id and namespace_id identifiers within the broker subject limit.",
                    "Keep the combined apex.events scope subject at or below 256 bytes.",
                ],
            },
            GatewayErrorCode::InvalidRetryConfiguration => Self {
                code,
                summary: "The durable publisher retry configuration is invalid.",
                cause: "Retry attempts must be between 1 and 8 to bound duplicate delivery, downstream load, and ambiguous acknowledgements.",
                retryable: false,
                recommended_next_steps: &[
                    "Configure max_attempts as an integer from 1 through 8 for the transport or downstream sink.",
                    "Use the event ID as the durable idempotency key when enabling retries.",
                ],
            },
            GatewayErrorCode::InvalidNatsConfiguration => Self {
                code,
                summary: "The NATS TLS transport configuration is invalid.",
                cause: "The transport requires a TLS endpoint without embedded credentials and certificate files that are regular files inside the trusted secret directory.",
                retryable: false,
                recommended_next_steps: &[
                    "Use a tls:// endpoint with a hostname or address and no userinfo, query, fragment, or control characters.",
                    "Keep the CA certificate, client certificate, and private key as regular files within the configured trusted base directory.",
                ],
            },
            GatewayErrorCode::InvalidNatsPublishRequest => Self {
                code,
                summary: "The NATS transport rejected an unsafe publish request.",
                cause: "The subject, message ID, or payload did not satisfy the bounded publish contract before broker I/O.",
                retryable: false,
                recommended_next_steps: &[
                    "Use a non-wildcard ASCII subject with non-empty dot-delimited tokens and a bounded event message ID.",
                    "Send a non-empty payload no larger than the configured 256 KiB envelope limit.",
                ],
            },
            GatewayErrorCode::NatsConnectionFailed => Self {
                code,
                summary: "The ingest service could not establish a durable NATS connection.",
                cause: "The TLS connection or JetStream control-plane handshake did not complete within the bounded connection policy.",
                retryable: true,
                recommended_next_steps: &[
                    "Check NATS server health, JetStream availability, and the service network path.",
                    "Verify the configured CA, client certificate, private key, and NATS permissions without logging their contents.",
                ],
            },
            GatewayErrorCode::IdempotencyConflict => Self {
                code,
                summary: "The event_id was already accepted for a different event payload.",
                cause: "Idempotency keys are bound to the original canonical payload and cannot be reused to acknowledge a changed event.",
                retryable: false,
                recommended_next_steps: &[
                    "Use the original payload when replaying an accepted event_id.",
                    "Generate a new UUIDv7 event_id for a genuinely different event.",
                ],
            },
            GatewayErrorCode::InvalidSinkConfiguration => Self {
                code,
                summary: "A durable ClickHouse or archive sink configuration is invalid.",
                cause: "The sink requires an HTTPS endpoint and trusted mTLS credentials within the configured secret directory.",
                retryable: false,
                recommended_next_steps: &[
                    "Use an HTTPS endpoint without embedded credentials or query parameters.",
                    "Verify the CA, client certificate, private key, and optional bearer-token files are regular files inside the trusted secret directory.",
                ],
            },
        }
    }

    pub fn grpc_status(&self) -> &'static str {
        match self.code {
            GatewayErrorCode::Unauthenticated => "UNAUTHENTICATED",
            GatewayErrorCode::InvalidAuthorization => "UNAUTHENTICATED",
            GatewayErrorCode::ScopeDenied => "PERMISSION_DENIED",
            GatewayErrorCode::InvalidEventId => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidEnvelope => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidStructure => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidTimestamp => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidIntegrity => "INVALID_ARGUMENT",
            GatewayErrorCode::PayloadTooLarge => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::IdempotencyCapacity => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::PublishFailed => "UNAVAILABLE",
            GatewayErrorCode::Internal => "INTERNAL",
            GatewayErrorCode::SubjectTooLong => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidRetryConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidNatsConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidNatsPublishRequest => "INVALID_ARGUMENT",
            GatewayErrorCode::NatsConnectionFailed => "UNAVAILABLE",
            GatewayErrorCode::IdempotencyConflict => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidSinkConfiguration => "INVALID_ARGUMENT",
        }
    }

    pub(crate) fn grpc_status_value(&self) -> tonic::Status {
        let code = match self.grpc_status() {
            "UNAUTHENTICATED" => tonic::Code::Unauthenticated,
            "PERMISSION_DENIED" => tonic::Code::PermissionDenied,
            "RESOURCE_EXHAUSTED" => tonic::Code::ResourceExhausted,
            "UNAVAILABLE" => tonic::Code::Unavailable,
            "INTERNAL" => tonic::Code::Internal,
            _ => tonic::Code::InvalidArgument,
        };
        // All fields are static, reviewed guidance; never include raw transport
        // errors, caller identity, credentials, or event payload data here.
        let next_step = self
            .recommended_next_steps
            .first()
            .copied()
            .unwrap_or("Follow the documented recovery procedure.");
        tonic::Status::new(
            code,
            format!(
                "{}: {} Cause: {} Next: {}",
                self.code.as_str(),
                self.summary,
                self.cause,
                next_step
            ),
        )
    }

    pub fn diagnostic_report(
        &self,
        component: impl Into<String>,
        workspace_id: impl Into<String>,
        namespace_id: impl Into<String>,
        event_id: Option<&str>,
    ) -> GatewayDiagnosticReport {
        // Diagnostic reports may be sent to AI-assisted troubleshooting tools.  Keep
        // caller-provided labels within a strict identifier grammar so they cannot
        // create Markdown structure or instructions in that handoff.
        let component = safe_diagnostic_identifier(component.into());
        let workspace_id = safe_diagnostic_identifier(workspace_id.into());
        let namespace_id = safe_diagnostic_identifier(namespace_id.into());
        let category = self.category();
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(format!("{component}:{category}:{}", self.code.as_str()).as_bytes())
        );
        GatewayDiagnosticReport {
            report_id: uuid7_report_id(),
            fingerprint,
            severity: "error",
            status: "open",
            scope: DiagnosticScope {
                workspace_id,
                namespace_id,
            },
            correlation: DiagnosticCorrelation {
                event_id: event_id
                    .filter(|id| is_lowercase_uuidv7(id))
                    .map(str::to_owned),
            },
            failure: DiagnosticFailure {
                code: self.code,
                category,
                retryable: self.retryable,
            },
            summary: self.summary,
            cause: self.cause,
            causal_chain: vec!["event-ingest:admission"],
            evidence: DiagnosticEvidence {
                component,
                stage: "admission",
            },
            redaction_summary: RedactionSummary {
                omitted_fields: vec!["envelope", "caller_subject", "raw_error"],
            },
            recommended_next_steps: self.recommended_next_steps,
        }
    }

    fn category(&self) -> &'static str {
        match self.code {
            GatewayErrorCode::Unauthenticated | GatewayErrorCode::InvalidAuthorization => {
                "authentication"
            }
            GatewayErrorCode::ScopeDenied => "authorization",
            GatewayErrorCode::InvalidEventId
            | GatewayErrorCode::InvalidEnvelope
            | GatewayErrorCode::InvalidStructure
            | GatewayErrorCode::InvalidTimestamp
            | GatewayErrorCode::InvalidIntegrity
            | GatewayErrorCode::PayloadTooLarge => "validation",
            GatewayErrorCode::IdempotencyCapacity => "durability",
            GatewayErrorCode::PublishFailed => "durability",
            GatewayErrorCode::Internal => "runtime",
            GatewayErrorCode::SubjectTooLong => "validation",
            GatewayErrorCode::InvalidRetryConfiguration => "configuration",
            GatewayErrorCode::InvalidNatsConfiguration => "configuration",
            GatewayErrorCode::InvalidNatsPublishRequest => "validation",
            GatewayErrorCode::NatsConnectionFailed => "durability",
            GatewayErrorCode::IdempotencyConflict => "validation",
            GatewayErrorCode::InvalidSinkConfiguration => "configuration",
        }
    }
}

fn safe_diagnostic_identifier(value: String) -> String {
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

fn uuid7_report_id() -> String {
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
