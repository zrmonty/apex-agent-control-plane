"""Retrying event-idempotent delivery adapter for the generated gRPC client."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from time import sleep
from typing import Any, Callable, Protocol

from .errors import ApexError, ConfigurationError
from .event import canonical_event_bytes
from .validation import EventValidationError, validate_event


class GrpcIngestTransport(Protocol):
    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool: ...

    def close(self) -> None: ...


class ExportDeliveryError(ApexError):
    code = "EVENT_EXPORT_FAILED"
    category = "ingest"
    retryable = True
    safe_message = "The event could not be delivered to ingest."
    cause = "The ingest transport did not acknowledge the event."
    recommended_next_steps = ("Check the ingest endpoint health and network reachability.", "Use the event_id to verify whether ingest stored the event before replaying it.")

    def __init__(self, message: str | None = None, *, correlation: Mapping[str, str] | None = None, code: str | None = None, category: str | None = None, retryable: bool | None = None, cause: str | None = None, recommended_next_steps: tuple[str, ...] | None = None, context: Mapping[str, str | int | bool] | None = None) -> None:
        super().__init__(message, correlation=correlation, cause=cause, recommended_next_steps=recommended_next_steps, context=context)
        if code is not None:
            self.code = code
        if category is not None:
            self.category = category
        if retryable is not None:
            self.retryable = retryable


class GrpcStatusError(Exception):
    """Transport adapter error carrying a gRPC status without exposing its message."""

    def __init__(self, status: str, message: str = "") -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class _ExporterStats:
    attempted: int
    delivered: int
    duplicates: int
    failed: int

    def as_dict(self) -> dict[str, int]:
        return {"attempted": self.attempted, "delivered": self.delivered, "duplicates": self.duplicates, "failed": self.failed}


class BoundedGrpcExporter:
    """Retries a bounded number of delivery attempts using the original event ID."""

    def __init__(self, transport: GrpcIngestTransport, *, max_attempts: int = 3, failure_threshold: int = 5, backoff: Callable[[int], float] | None = None, sleeper: Callable[[float], None] = sleep) -> None:
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
            raise ConfigurationError("exporter max_attempts must be at least one")
        if not isinstance(failure_threshold, int) or isinstance(failure_threshold, bool) or failure_threshold < 1:
            raise ConfigurationError("exporter failure_threshold must be at least one")
        self._transport = transport
        self._max_attempts = max_attempts
        self._failure_threshold = failure_threshold
        self._backoff = backoff or (lambda attempt: min(0.1 * (2 ** (attempt - 1)), 1.0))
        self._sleeper = sleeper
        self._lock = Lock()
        self._stats = _ExporterStats(0, 0, 0, 0)
        self._consecutive_failures = 0

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return self._stats.as_dict()

    def write(self, event: dict[str, Any]) -> None:
        try:
            validate_event(event)
        except EventValidationError as exc:
            raise ExportDeliveryError(
                "The event was rejected before export because it does not meet the Apex contract.",
                code="EVENT_EXPORT_PRECONDITION_FAILED",
                category="contract",
                retryable=False,
                cause="Local event validation failed before any transport request was attempted.",
                recommended_next_steps=(
                    "Correct the event using the Apex v1 schema and recompute its event_hash.",
                    "Use validation_code with the event builder or validator to identify the failed contract rule.",
                ),
                context={"validation_code": exc.code},
            ) from exc
        event_id = event["event_id"]
        correlation = {"event_id": event_id}
        with self._lock:
            if self._consecutive_failures >= self._failure_threshold:
                raise ExportDeliveryError("Ingest delivery circuit is open after repeated failures.", correlation=correlation, code="INGEST_CIRCUIT_OPEN", category="ingest", retryable=True, cause="The exporter reached its consecutive delivery-failure threshold.", recommended_next_steps=("Wait for ingest health to recover before retrying.", "Check recent ingest diagnostics using the event_id."), context={"failure_threshold": self._failure_threshold})
        failure: ExportDeliveryError | None = None
        for attempt in range(1, self._max_attempts + 1):
            self._increment("attempted")
            try:
                inserted = self._transport.ingest(event, event_id=event_id)
                if not isinstance(inserted, bool):
                    failure = ExportDeliveryError("Ingest returned an invalid acknowledgement.", correlation=correlation, code="INGEST_PROTOCOL_VIOLATION", category="ingest", retryable=False, cause="The gRPC transport returned a response that was not an acknowledgement boolean.", recommended_next_steps=("Verify the generated gRPC client and ingest service use the same contract version.",))
                    break
            except Exception as exc:
                failure = self._classify_failure(exc, correlation)
                if not failure.retryable:
                    break
                if attempt < self._max_attempts:
                    delay = self._backoff(attempt)
                    if delay > 0:
                        self._sleeper(delay)
                continue
            self._increment("delivered" if inserted else "duplicates")
            with self._lock:
                self._consecutive_failures = 0
            return
        self._increment("failed")
        if failure is not None:
            failure.context["attempt_count"] = attempt
        with self._lock:
            self._consecutive_failures += 1
        raise failure or ExportDeliveryError(correlation=correlation)

    def close(self) -> None:
        try:
            self._transport.close()
        except Exception as exc:
            raise ExportDeliveryError(
                "The ingest transport could not be closed cleanly.",
                code="INGEST_TRANSPORT_CLOSE_FAILED",
                category="ingest",
                retryable=True,
                cause="The transport raised an untyped error during ingest connection close.",
                recommended_next_steps=("Retry shutdown after the ingest transport recovers.", "Inspect the transport's safe operational diagnostics for connection-close failures."),
            ) from exc

    def _increment(self, field: str) -> None:
        with self._lock:
            values = self._stats.as_dict()
            values[field] += 1
            self._stats = _ExporterStats(**values)

    @staticmethod
    def _classify_failure(error: Exception, correlation: Mapping[str, str]) -> ExportDeliveryError:
        if not isinstance(error, GrpcStatusError):
            return ExportDeliveryError(correlation=correlation)
        status = error.status.upper()
        if status not in {"UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "DEADLINE_EXCEEDED", "RESOURCE_EXHAUSTED"}:
            return ExportDeliveryError("Ingest rejected the event request.", correlation=correlation, code="INGEST_REQUEST_REJECTED", category="ingest", retryable=False, cause="The gRPC endpoint returned an unrecognized status.", recommended_next_steps=("Validate the generated gRPC client and ingest service versions.", "Inspect the ingest service's safe diagnostic record for the event_id."), context={"grpc_status": "UNRECOGNIZED"})
        if status == "UNAUTHENTICATED":
            return ExportDeliveryError("Ingest rejected the SDK authentication.", correlation=correlation, code="INGEST_AUTHENTICATION_FAILED", category="authentication", retryable=False, cause="The gRPC endpoint returned UNAUTHENTICATED.", recommended_next_steps=("Verify the workload identity or bearer token is present and not expired.", "Confirm the ingest endpoint trusts the configured issuer."), context={"grpc_status": status})
        if status == "PERMISSION_DENIED":
            return ExportDeliveryError("Ingest denied this SDK identity.", correlation=correlation, code="INGEST_AUTHORIZATION_FAILED", category="authorization", retryable=False, cause="The gRPC endpoint returned PERMISSION_DENIED.", recommended_next_steps=("Verify the workload identity has ingest permission for the event scope.",), context={"grpc_status": status})
        if status in {"UNAVAILABLE", "DEADLINE_EXCEEDED"}:
            return ExportDeliveryError("Ingest is temporarily unavailable after the configured retry attempts.", correlation=correlation, code="INGEST_UNAVAILABLE", category="ingest", retryable=True, cause=f"The gRPC endpoint returned {status}.", recommended_next_steps=("Check ingest endpoint health and network reachability.", "Retry using the same event_id after the endpoint recovers."), context={"grpc_status": status})
        if status == "RESOURCE_EXHAUSTED":
            return ExportDeliveryError("Ingest is rate-limiting event delivery.", correlation=correlation, code="INGEST_RATE_LIMITED", category="ingest", retryable=True, cause="The gRPC endpoint returned RESOURCE_EXHAUSTED.", recommended_next_steps=("Reduce exporter concurrency or wait for ingest capacity.", "Inspect ingest queue and rate-limit metrics."), context={"grpc_status": status})
        return ExportDeliveryError("Ingest rejected the event request.", correlation=correlation, code="INGEST_REQUEST_REJECTED", category="ingest", retryable=False, cause="The gRPC endpoint rejected the request.", recommended_next_steps=("Validate the event against the ingest contract.", "Inspect the ingest service's safe diagnostic record for the event_id."), context={"grpc_status": "UNRECOGNIZED"})


class InMemoryIdempotentIngest:
    """Deterministic contract-test harness for an event_id idempotency boundary."""

    def __init__(self) -> None:
        self._events: dict[str, dict[str, Any]] = {}
        self._fingerprints: dict[str, bytes] = {}

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events.values())

    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool:
        if event_id in self._events:
            if self._fingerprints[event_id] != canonical_event_bytes(event):
                raise GrpcStatusError("INVALID_ARGUMENT", "event_id payload conflict")
            return False
        self._events[event_id] = dict(event)
        self._fingerprints[event_id] = canonical_event_bytes(event)
        return True

    def close(self) -> None:
        return
