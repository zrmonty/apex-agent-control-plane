"""Targeted tests to close remaining coverage gaps toward 95%."""

from __future__ import annotations

from time import monotonic

import pytest

from apex_sdk import (
    AgentTemplateError,
    ConfigurationError,
    EventBuilder,
    TelemetryMappingError,
    assess_agent_template,
    gold_standard_controls,
    gold_standard_manifest,
    to_otel_attributes,
)
from apex_sdk.errors import ApexError, _safe_next_steps
from apex_sdk.exporter import BoundedGrpcExporter, ExportDeliveryError, GrpcStatusError, InMemoryIdempotentIngest
from apex_sdk.observer import BoundedObserver
from apex_sdk.template import GOLD_STANDARD_CONTROLS, TEMPLATE_VERSION


EVENT_ID = "018f5c91-2d88-7c00-8000-000000000001"


def event(event_id: str = EVENT_ID) -> dict:
    return EventBuilder(
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        actor={"type": "agent", "id": "agent"},
        version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
    ).build("turn_start", {}, event_id=event_id)


def test_exporter_rejects_non_integer_failure_threshold() -> None:
    with pytest.raises(ConfigurationError, match="failure_threshold"):
        BoundedGrpcExporter(InMemoryIdempotentIngest(), failure_threshold=True)  # type: ignore[arg-type]


def test_idempotent_ingest_rejects_conflicting_payload_for_same_event_id() -> None:
    ingest = InMemoryIdempotentIngest()
    first = event()
    second = event()
    second = EventBuilder(
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        actor={"type": "agent", "id": "agent"},
        version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
    ).build("turn_end", {"status": "ok"}, event_id=EVENT_ID)
    assert ingest.ingest(first, event_id=EVENT_ID) is True
    with pytest.raises(GrpcStatusError) as raised:
        ingest.ingest(second, event_id=EVENT_ID)
    assert raised.value.status == "INVALID_ARGUMENT"
    ingest.close()


def test_circuit_half_open_allows_probe_after_cooldown() -> None:
    class OnceFail:
        def __init__(self) -> None:
            self.calls = 0

        def ingest(self, event: dict, *, event_id: str) -> bool:
            self.calls += 1
            if self.calls == 1:
                raise GrpcStatusError("UNAVAILABLE", "down")
            return True

        def close(self) -> None:
            return

    transport = OnceFail()
    exporter = BoundedGrpcExporter(transport, max_attempts=1, failure_threshold=1)
    exporter._circuit_cooldown_seconds = 0.0
    with pytest.raises(ExportDeliveryError):
        exporter.write(event())
    exporter._circuit_opened_at = monotonic() - 1.0
    exporter.write(event("018f5c91-2d88-7c00-8000-000000000002"))
    assert transport.calls == 2


def test_template_gaps_cover_severity_and_control_bounds() -> None:
    controls = gold_standard_controls(enabled=True)
    first = next(iter(GOLD_STANDARD_CONTROLS))
    controls[first] = False
    assessment = assess_agent_template(
        {"template_version": TEMPLATE_VERSION, "agent_code": "agent", "controls": controls}
    )
    assert assessment.compliant is False
    assert assessment.severity in {"medium", "high"}
    assert assessment.security_finding() is not None

    # Same cardinality as the gold set, but one unsupported name.
    almost = gold_standard_controls(enabled=True)
    almost.pop(first)
    almost["not_a_real_control"] = True
    with pytest.raises(AgentTemplateError, match="unsupported controls"):
        assess_agent_template(
            {
                "template_version": TEMPLATE_VERSION,
                "agent_code": "agent",
                "controls": almost,
            }
        )

    bloated = gold_standard_controls(enabled=True)
    for i in range(3):
        bloated[f"extra{i}"] = True
    with pytest.raises(AgentTemplateError, match="exceed"):
        assess_agent_template(
            {"template_version": TEMPLATE_VERSION, "agent_code": "agent", "controls": bloated}
        )

    compliant = assess_agent_template(gold_standard_manifest("agent"))
    assert compliant.severity == "info"


def test_telemetry_rejects_non_object_and_bad_identifiers() -> None:
    with pytest.raises(TelemetryMappingError):
        to_otel_attributes([])  # type: ignore[arg-type]
    with pytest.raises(TelemetryMappingError):
        to_otel_attributes(
            {
                "type": "turn_start",
                "agent_id": "bad id",
                "run_id": "run",
                "trace_id": "trace",
                "scope": {"workspace_id": "w", "namespace_id": "n", "agent_group_ids": []},
                "version": {"agent_code": "a", "prompt": "p", "model": "m"},
                "data": {},
            }
        )


def test_observer_drop_reporter_and_double_close() -> None:
    class Sink:
        def write(self, event: dict) -> None:
            return

        def close(self) -> None:
            return

    def bad_reporter(reason: str) -> None:
        raise RuntimeError("metrics down")

    observer = BoundedObserver(Sink(), capacity=1, drop_reporter=bad_reporter)
    assert observer.emit({"not": "valid"}) is False
    assert observer.close(timeout=0.5) is True
    assert observer.close(timeout=0) is True


def test_safe_next_steps_fallback_on_empty_tuple() -> None:
    assert _safe_next_steps(()) == ApexError.recommended_next_steps


def test_validation_require_exact_fields_missing_and_secret_value_shapes() -> None:
    from apex_sdk.validation import (
        _contains_secret_like,
        _encoded_secret,
        _has_sensitive_value,
        _require_exact_fields,
        validate_event,
    )
    from apex_sdk import EventValidationError

    with pytest.raises(EventValidationError, match="missing required fields"):
        _require_exact_fields({"a": 1}, {"a", "b"}, "scope")

    assert _encoded_secret("a" * 64) is True  # pure hex path
    assert _encoded_secret("not-hex-but-long-enough-value-with_mixed_chars_0123456789") is True
    assert _has_sensitive_value(None) is False
    assert _has_sensitive_value({"nested": "x"}) is True
    assert _has_sensitive_value(["token"]) is True
    assert _has_sensitive_value(1) is True
    assert _contains_secret_like({"password": None}) is False
    assert _contains_secret_like({"password": {"inner": "secret"}}) is True
    assert _contains_secret_like({"password": ["x"]}) is True

    # Missing integrity subfields exercise _require_exact_fields missing branch via validate_event.
    payload = event()
    del payload["integrity"]["event_hash"]
    with pytest.raises(EventValidationError, match="missing required fields"):
        validate_event(payload)


def test_control_inject_rejects_non_utf8_content() -> None:
    from apex_sdk.validation import _validate_control_data
    from apex_sdk import EventValidationError

    class BadStr(str):
        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:  # type: ignore[override]
            raise UnicodeEncodeError("utf-8", "x", 0, 1, "boom")

    with pytest.raises(EventValidationError, match="UTF-8"):
        _validate_control_data(
            {
                "action": "inject",
                "enforcement": "cooperative",
                "reason_code": None,
                "parameters": {
                    "content": BadStr("payload"),
                    "content_classification": "untrusted",
                },
            }
        )


def test_permission_denied_and_rate_limit_status_mapping() -> None:
    class Status:
        def __init__(self, status: str) -> None:
            self.status = status

        def ingest(self, event: dict, *, event_id: str) -> bool:
            raise GrpcStatusError(self.status, "detail")

        def close(self) -> None:
            return

    with pytest.raises(ExportDeliveryError) as denied:
        BoundedGrpcExporter(Status("PERMISSION_DENIED"), max_attempts=1).write(event())
    assert denied.value.code == "INGEST_AUTHORIZATION_FAILED"

    with pytest.raises(ExportDeliveryError) as limited:
        BoundedGrpcExporter(Status("RESOURCE_EXHAUSTED"), max_attempts=1).write(event())
    assert limited.value.code == "INGEST_RATE_LIMITED"
