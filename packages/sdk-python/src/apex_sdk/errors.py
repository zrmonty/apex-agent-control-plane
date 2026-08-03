"""Safe, typed errors intended for diagnostics and API boundaries."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_SENSITIVE_TEXT = re.compile(
    r"(?:api[_-]?key|authorization|password|secret|token)\s*(?:=|:)\s*\S+"
    r"|bearer\s+\S+"
    r"|-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----"
    r"|\b(?:eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}|sk-[a-zA-Z0-9_-]{16,})\b",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_CORRELATION_KEYS = frozenset({"event_id", "trace_id", "run_id"})
_SAFE_CONTEXT_KEYS = frozenset({"grpc_status", "attempt_count", "failure_threshold", "validation_code"})
_KNOWN_GRPC_STATUSES = frozenset({"ABORTED", "ALREADY_EXISTS", "CANCELLED", "DATA_LOSS", "DEADLINE_EXCEEDED", "FAILED_PRECONDITION", "INTERNAL", "INVALID_ARGUMENT", "NOT_FOUND", "OUT_OF_RANGE", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "UNAUTHENTICATED", "UNAVAILABLE", "UNIMPLEMENTED", "UNKNOWN", "UNRECOGNIZED"})


def _safe_text(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    if len(value) > 512 or any(ord(character) < 32 for character in value) or _SENSITIVE_TEXT.search(value):
        return fallback
    return value


def _safe_next_steps(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        return ApexError.recommended_next_steps
    return tuple(_safe_text(step, "Follow the documented recovery procedure.") for step in value)


def _safe_identifier(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_IDENTIFIER.fullmatch(value) else None


def _safe_correlation(correlation: Mapping[str, str] | None) -> dict[str, str]:
    return {key: value for key, value in (correlation or {}).items() if key in _SAFE_CORRELATION_KEYS and _safe_identifier(value) is not None}


def _safe_context(context: Mapping[str, str | int | bool] | None) -> dict[str, str | int]:
    safe: dict[str, str | int] = {}
    for key, value in (context or {}).items():
        if key not in _SAFE_CONTEXT_KEYS:
            continue
        if key == "grpc_status" and isinstance(value, str) and value in _KNOWN_GRPC_STATUSES:
            safe[key] = value
        elif key == "validation_code" and _safe_identifier(value) is not None:
            safe[key] = value
        elif key != "grpc_status" and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            safe[key] = value
    return safe


class ApexError(ValueError):
    code = "APEX_OPERATION_FAILED"
    category = "runtime"
    retryable = False
    safe_message = "The Apex operation could not be completed."
    cause = "The operation failed at a protected SDK boundary."
    recommended_next_steps = ("Use the correlation IDs to locate the related event or trace.",)

    def __init__(self, message: str | None = None, *, correlation: Mapping[str, str] | None = None, cause: str | None = None, recommended_next_steps: tuple[str, ...] | None = None, context: Mapping[str, str | int | bool] | None = None) -> None:
        self.summary = _safe_text(message, self.safe_message)
        super().__init__(self.summary)
        self.correlation = _safe_correlation(correlation)
        self.cause = _safe_text(cause, self.cause)
        if recommended_next_steps is not None:
            safe_steps = _safe_next_steps(recommended_next_steps)
            self.recommended_next_steps = safe_steps or self.recommended_next_steps
        self.context = _safe_context(context)

    def to_diagnostic(self) -> dict[str, Any]:
        return {"summary": self.summary, "cause": self.cause, "recommended_next_steps": self.recommended_next_steps, "context": dict(self.context)}


class ConfigurationError(ApexError):
    code = "APEX_CONFIGURATION_INVALID"
    category = "configuration"
    safe_message = "The Apex SDK configuration is not valid."
    cause = "A protected SDK boundary rejected an invalid local configuration value."
    recommended_next_steps = ("Correct the configuration value and retry initialization.", "Keep configured file paths within their approved base directory.")


class EventIntegrityError(ApexError):
    code = "EVENT_CANONICALIZATION_FAILED"
    category = "integrity"
    safe_message = "The event could not be canonically encoded."
    cause = "The event contains a value that is not valid RFC 8785 canonical JSON."
    recommended_next_steps = ("Remove NaN, Infinity, binary values, and unsupported custom objects from event data.", "Validate the event against the Apex schema before retrying.")


class TelemetryMappingError(ApexError):
    code = "TELEMETRY_MAPPING_FAILED"
    category = "telemetry"
    safe_message = "Telemetry export could not be prepared."
    cause = "A required Apex event field was missing or had an incompatible shape for telemetry export."
    recommended_next_steps = ("Validate the event envelope before mapping telemetry.", "For LLM events, provide provider, model, input_tokens, and output_tokens.")


class ObserverExportError(ApexError):
    code = "OBSERVER_EXPORT_FAILED"
    category = "telemetry"
    retryable = True
    safe_message = "Event export failed in the background observer."
    cause = "The configured event sink raised an untyped exception."
    recommended_next_steps = ("Inspect the sink health and its safe diagnostic record.", "Retry delivery from the durable event path when available.")
