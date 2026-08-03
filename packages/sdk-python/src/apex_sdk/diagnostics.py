"""Redacted, immutable in-process diagnostic reports for SDK failures."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from uuid import UUID

from .errors import ApexError, ConfigurationError, _safe_context, _safe_correlation, _safe_identifier, _safe_next_steps, _safe_text

MAX_DIAGNOSTIC_RECORD_BYTES = 256 * 1024
MAX_DIAGNOSTIC_SPOOL_BYTES = 64 * 1024 * 1024
MAX_IN_MEMORY_REPORTS = 10_000


def _uuid7() -> str:
    timestamp_ms = int(time.time() * 1_000).to_bytes(6, "big")
    random_bytes = bytearray(os.urandom(10))
    random_bytes[0] = (random_bytes[0] & 0x0F) | 0x70
    random_bytes[2] = (random_bytes[2] & 0x3F) | 0x80
    return str(UUID(bytes=timestamp_ms + bytes(random_bytes)))


@dataclass(frozen=True)
class DiagnosticReport:
    report_id: str
    fingerprint: str
    severity: str
    status: str
    correlation: dict[str, str]
    failure: dict[str, str | bool]
    summary: str
    cause: str
    evidence: dict[str, str | int | bool]
    recommended_next_steps: tuple[str, ...]

    def to_ai_payload(self) -> dict[str, object]:
        safe_component = _safe_identifier(self.evidence.get("component")) or "[redacted invalid identifier]"
        safe_error_type = _safe_identifier(self.evidence.get("error_type")) or "[redacted invalid identifier]"
        safe_failure = {
            "code": _safe_identifier(self.failure.get("code")) or "[redacted invalid identifier]",
            "category": _safe_identifier(self.failure.get("category")) or "[redacted invalid identifier]",
            "retryable": self.failure.get("retryable") if isinstance(self.failure.get("retryable"), bool) else False,
        }
        return {
            "report_id": _safe_identifier(self.report_id) or "[redacted invalid identifier]",
            "fingerprint": _safe_identifier(self.fingerprint) or "[redacted invalid identifier]",
            "summary": _safe_text(self.summary, ApexError.safe_message),
            "cause": _safe_text(self.cause, ApexError.cause),
            "failure": safe_failure,
            "correlation": _safe_correlation(self.correlation),
            "evidence": {"component": safe_component, "error_type": safe_error_type, **_safe_context(self.evidence)},
            "recommended_next_steps": tuple(_safe_text(step, "Follow the documented recovery procedure.") for step in self.recommended_next_steps),
        }


class DiagnosticReporter:
    """Keeps safe reports locally; callers can forward them through a durable path."""

    def __init__(self) -> None:
        self._reports: deque[DiagnosticReport] = deque(maxlen=MAX_IN_MEMORY_REPORTS)
        self._lock = Lock()

    @property
    def reports(self) -> tuple[DiagnosticReport, ...]:
        with self._lock:
            return tuple(self._reports)

    def capture(self, error: ApexError, *, component: str) -> DiagnosticReport:
        safe_component = _safe_identifier(component) or "[redacted invalid identifier]"
        code = _safe_identifier(error.code) or ApexError.code
        category = _safe_identifier(error.category) or ApexError.category
        retryable = error.retryable if isinstance(error.retryable, bool) else False
        summary = _safe_text(error.summary, ApexError.safe_message)
        cause = _safe_text(error.cause, ApexError.cause)
        next_steps = _safe_next_steps(error.recommended_next_steps)
        fingerprint = hashlib.sha256(f"{safe_component}:{category}:{code}".encode()).hexdigest()
        report = DiagnosticReport(
            report_id=_uuid7(),
            fingerprint=fingerprint,
            severity="error",
            status="open",
            correlation=_safe_correlation(error.correlation),
            failure={"code": code, "category": category, "retryable": retryable},
            summary=summary,
            cause=cause,
            evidence={"component": safe_component, "error_type": type(error).__name__, **_safe_context(error.context)},
            recommended_next_steps=next_steps,
        )
        with self._lock:
            self._reports.append(report)
        return report


class EmergencySpool:
    """Last-resort local record when the primary diagnostic reporter fails."""

    def __init__(self, path: str | Path, *, base_dir: str | Path) -> None:
        try:
            requested_path = Path(path)
            if requested_path.is_symlink():
                raise ConfigurationError("emergency spool path must not be a symbolic link")
            base_path = Path(base_dir).resolve(strict=True)
            resolved_path = requested_path.resolve(strict=False)
        except OSError as exc:
            raise ConfigurationError("emergency spool paths must resolve within an existing configured base directory") from exc
        if resolved_path != base_path and base_path not in resolved_path.parents:
            raise ConfigurationError("emergency spool path must remain within the configured base directory")
        self._path = resolved_path
        self._lock = Lock()

    def write(self, error: ApexError, *, component: str) -> None:
        safe_component = _safe_identifier(component) or "[redacted invalid identifier]"
        code = _safe_identifier(error.code) or ApexError.code
        category = _safe_identifier(error.category) or ApexError.category
        fingerprint = hashlib.sha256(f"{safe_component}:{category}:{code}".encode()).hexdigest()
        record = {"timestamp": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"), "component": safe_component, "code": code, "fingerprint": fingerprint, "summary": _safe_text(error.summary, ApexError.safe_message), "cause": _safe_text(error.cause, ApexError.cause), "correlation": _safe_correlation(error.correlation), "recommended_next_steps": _safe_next_steps(error.recommended_next_steps)}
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_DIAGNOSTIC_RECORD_BYTES:
            raise ConfigurationError("diagnostic record exceeds the emergency spool record limit")
        with self._lock:
            try:
                current_size = self._path.stat().st_size if self._path.exists() else 0
            except OSError as exc:
                raise ConfigurationError("emergency spool size could not be checked") from exc
            if current_size + len(encoded) > MAX_DIAGNOSTIC_SPOOL_BYTES:
                raise ConfigurationError("emergency spool reached its storage limit; rotate it before retrying")
            with self._path.open("ab") as spool:
                spool.write(encoded)
