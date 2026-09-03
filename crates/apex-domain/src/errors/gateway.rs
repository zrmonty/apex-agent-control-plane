use sha2::{Digest, Sha256};

use super::code::GatewayErrorCode;
use super::diagnostics::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, RedactionSummary, safe_diagnostic_identifier, uuid7_report_id,
};
use crate::is_lowercase_uuidv7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError {
    pub code: GatewayErrorCode,
    pub summary: &'static str,
    pub cause: &'static str,
    pub retryable: bool,
    pub recommended_next_steps: &'static [&'static str],
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

    pub fn invalid_outbox_configuration() -> Self {
        Self::new(GatewayErrorCode::InvalidOutboxConfiguration)
    }

    pub fn invalid_idempotency_configuration() -> Self {
        Self::new(GatewayErrorCode::InvalidIdempotencyConfiguration)
    }

    pub fn idempotency_conflict() -> Self {
        Self::new(GatewayErrorCode::IdempotencyConflict)
    }

    pub fn new(code: GatewayErrorCode) -> Self {
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
            GatewayErrorCode::SecretExposure => Self {
                code,
                summary: "Ingest rejected an event containing a credential-like value.",
                cause: "The server-side content policy detected secret material in a non-control event payload.",
                retryable: false,
                recommended_next_steps: &[
                    "Remove credentials and secret-bearing fields before retrying.",
                    "Send references or redacted hashes instead of secret material.",
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
                cause: "The configured idempotency boundary reached its bounded capacity and will not evict committed keys implicitly.",
                retryable: true,
                recommended_next_steps: &[
                    "Restore or configure the durable idempotency store.",
                    "Retry the same event_id only after capacity is available.",
                ],
            },
            GatewayErrorCode::IdempotencyInProgress => Self {
                code,
                summary: "The event is currently being published by another request.",
                cause: "An idempotency reservation exists but has not committed, so acknowledging this request would risk a false duplicate success.",
                retryable: true,
                recommended_next_steps: &[
                    "Retry the same event_id after the in-flight publish completes.",
                    "Do not generate a new event_id for the same logical event.",
                ],
            },
            GatewayErrorCode::RateLimited => Self {
                code,
                summary: "The ingest authentication boundary is temporarily rate-limited.",
                cause: "The bounded admission budget for authentication attempts was exhausted.",
                retryable: true,
                recommended_next_steps: &[
                    "Reduce authentication probe frequency.",
                    "Retry after the server-provided backoff window.",
                ],
            },
            GatewayErrorCode::AdmissionBusy => Self {
                code,
                summary: "Ingest admission is temporarily busy.",
                cause: "A bounded live-admission or replay operation is using the gateway execution lane; the request was rejected without waiting indefinitely.",
                retryable: true,
                recommended_next_steps: &[
                    "Retry the same event_id with exponential backoff.",
                    "Inspect replay backlog and downstream sink latency if contention persists.",
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
            GatewayErrorCode::InvalidOutboxConfiguration => Self {
                code,
                summary: "The durable event outbox configuration is invalid.",
                cause: "The outbox path must be a regular append-only file inside the trusted persistence directory, or the PostgreSQL URL must use an approved transport. Remote PostgreSQL sessions require TLS and certificate verification.",
                retryable: false,
                recommended_next_steps: &[
                    "Set APEX_OUTBOX_FILE beneath APEX_OUTBOX_BASE on a persistent writable volume.",
                    "Inspect the outbox file for truncation or corruption without editing or deleting pending records.",
                    "For PostgreSQL, use sslmode=require and set APEX_POSTGRES_CA_FILE to the server CA bundle. Plaintext is accepted only for an explicit numeric loopback sslmode=disable development URL.",
                ],
            },
            GatewayErrorCode::InvalidIdempotencyConfiguration => Self {
                code,
                summary: "The durable idempotency store configuration is invalid.",
                cause: "The idempotency journal must be a bounded, parseable regular file inside the trusted persistence directory, or the PostgreSQL URL must use an approved transport. Remote PostgreSQL sessions require TLS and certificate verification.",
                retryable: false,
                recommended_next_steps: &[
                    "Set APEX_IDEMPOTENCY_FILE beneath APEX_IDEMPOTENCY_BASE on a persistent writable volume.",
                    "Inspect the idempotency journal for truncation or corruption without deleting committed records.",
                    "For PostgreSQL, use sslmode=require and set APEX_POSTGRES_CA_FILE to the server CA bundle. Plaintext is accepted only for an explicit numeric loopback sslmode=disable development URL.",
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
            GatewayErrorCode::SecretExposure => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidTimestamp => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidIntegrity => "INVALID_ARGUMENT",
            GatewayErrorCode::PayloadTooLarge => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::IdempotencyCapacity => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::IdempotencyInProgress => "ABORTED",
            GatewayErrorCode::RateLimited => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::AdmissionBusy => "RESOURCE_EXHAUSTED",
            GatewayErrorCode::PublishFailed => "UNAVAILABLE",
            GatewayErrorCode::Internal => "INTERNAL",
            GatewayErrorCode::SubjectTooLong => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidRetryConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidNatsConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidNatsPublishRequest => "INVALID_ARGUMENT",
            GatewayErrorCode::NatsConnectionFailed => "UNAVAILABLE",
            GatewayErrorCode::IdempotencyConflict => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidSinkConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidOutboxConfiguration => "INVALID_ARGUMENT",
            GatewayErrorCode::InvalidIdempotencyConfiguration => "INVALID_ARGUMENT",
        }
    }

    pub fn grpc_status_value(&self) -> tonic::Status {
        let code = match self.grpc_status() {
            "ABORTED" => tonic::Code::Aborted,
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
        let message = if matches!(
            self.code,
            GatewayErrorCode::Unauthenticated | GatewayErrorCode::InvalidAuthorization
        ) {
            "Authentication failed. Supply one valid bearer credential over the mTLS channel."
                .to_owned()
        } else if matches!(
            self.code,
            GatewayErrorCode::RateLimited | GatewayErrorCode::AdmissionBusy
        ) {
            "Request capacity is temporarily unavailable. Retry with exponential backoff."
                .to_owned()
        } else {
            format!(
                "{}: {} Cause: {} Next: {}",
                self.code.as_str(),
                self.summary,
                self.cause,
                next_step
            )
        };
        tonic::Status::new(code, message)
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
            Sha256::digest(
                format!("{component}:{category}:{}", self.code.public_code()).as_bytes()
            )
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
            | GatewayErrorCode::SecretExposure
            | GatewayErrorCode::InvalidTimestamp
            | GatewayErrorCode::InvalidIntegrity
            | GatewayErrorCode::PayloadTooLarge => "validation",
            GatewayErrorCode::IdempotencyCapacity => "durability",
            GatewayErrorCode::IdempotencyInProgress => "durability",
            GatewayErrorCode::RateLimited => "authentication",
            GatewayErrorCode::AdmissionBusy => "runtime",
            GatewayErrorCode::PublishFailed => "durability",
            GatewayErrorCode::Internal => "runtime",
            GatewayErrorCode::SubjectTooLong => "validation",
            GatewayErrorCode::InvalidRetryConfiguration => "configuration",
            GatewayErrorCode::InvalidNatsConfiguration => "configuration",
            GatewayErrorCode::InvalidNatsPublishRequest => "validation",
            GatewayErrorCode::NatsConnectionFailed => "durability",
            GatewayErrorCode::IdempotencyConflict => "validation",
            GatewayErrorCode::InvalidSinkConfiguration => "configuration",
            GatewayErrorCode::InvalidOutboxConfiguration => "configuration",
            GatewayErrorCode::InvalidIdempotencyConfiguration => "configuration",
        }
    }
}

