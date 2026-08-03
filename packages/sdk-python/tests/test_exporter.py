import pytest

from apex_sdk import ConfigurationError, EventBuilder
from apex_sdk.exporter import BoundedGrpcExporter, ExportDeliveryError, GrpcStatusError, InMemoryIdempotentIngest
from apex_sdk.diagnostics import DiagnosticReporter
from apex_sdk.observer import BoundedObserver


EVENT_ID = "018f5c91-2d88-7c00-8000-000000000001"


def event(event_id: str = EVENT_ID) -> dict:
    return EventBuilder(agent_id="agent", run_id="run-1", trace_id="trace-1", scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []}, actor={"type": "agent", "id": "agent"}, version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"}).build("turn_start", {}, event_id=event_id)


class FlakyTransport:
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls: list[str] = []

    def ingest(self, event: dict, *, event_id: str) -> bool:
        self.calls.append(event_id)
        if len(self.calls) <= self.failures:
            raise ConnectionError("endpoint unavailable")
        return True

    def close(self) -> None:
        pass


class StatusTransport:
    def __init__(self, status: str) -> None:
        self.status = status
        self.calls = 0

    def ingest(self, event: dict, *, event_id: str) -> bool:
        self.calls += 1
        raise GrpcStatusError(self.status, "token=secret")

    def close(self) -> None:
        pass


class InvalidResponseTransport:
    def ingest(self, event: dict, *, event_id: str):
        return "not-a-bool"

    def close(self) -> None:
        pass


class CloseFailingTransport:
    def ingest(self, event: dict, *, event_id: str) -> bool:
        return True

    def close(self) -> None:
        raise OSError("authorization=Bearer top-secret")


def test_exporter_retries_with_the_same_event_id() -> None:
    transport = FlakyTransport(failures=1)
    exporter = BoundedGrpcExporter(transport, max_attempts=2)

    exporter.write(event())

    assert transport.calls == [EVENT_ID, EVENT_ID]
    assert exporter.stats == {"attempted": 2, "delivered": 1, "duplicates": 0, "failed": 0}
    exporter.close()


def test_idempotent_ingest_rejects_duplicate_delivery_without_duplicate_storage() -> None:
    ingest = InMemoryIdempotentIngest()
    exporter = BoundedGrpcExporter(ingest, max_attempts=1)

    sent = event()
    exporter.write(sent)
    exporter.write(sent)

    assert ingest.events == (sent,)
    assert exporter.stats == {"attempted": 2, "delivered": 1, "duplicates": 1, "failed": 0}


def test_exporter_raises_typed_error_after_retry_budget_is_exhausted() -> None:
    exporter = BoundedGrpcExporter(FlakyTransport(failures=2), max_attempts=2)

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    assert raised.value.code == "EVENT_EXPORT_FAILED"
    assert raised.value.retryable is True
    assert raised.value.correlation == {"event_id": EVENT_ID}


def test_exporter_rejects_events_without_an_event_id() -> None:
    exporter = BoundedGrpcExporter(InMemoryIdempotentIngest())

    with pytest.raises(ExportDeliveryError, match="Apex contract") as raised:
        exporter.write({})

    assert raised.value.code == "EVENT_EXPORT_PRECONDITION_FAILED"
    assert raised.value.category == "contract"
    assert raised.value.retryable is False
    assert raised.value.cause == "Local event validation failed before any transport request was attempted."
    assert raised.value.context == {"validation_code": "EVENT_VALIDATION_FAILED"}


@pytest.mark.parametrize("max_attempts", [0, -1, "1", None, True])
def test_exporter_requires_a_positive_retry_budget(max_attempts: int) -> None:
    with pytest.raises(ConfigurationError, match="max_attempts"):
        BoundedGrpcExporter(InMemoryIdempotentIngest(), max_attempts=max_attempts)


def test_exporter_close_wraps_untyped_transport_errors() -> None:
    exporter = BoundedGrpcExporter(CloseFailingTransport())

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.close()

    assert raised.value.code == "INGEST_TRANSPORT_CLOSE_FAILED"
    assert raised.value.retryable is True
    assert "top-secret" not in str(raised.value)
    assert "close" in raised.value.cause.lower()


def test_observer_delivers_through_the_retrying_idempotent_exporter() -> None:
    transport = FlakyTransport(failures=1)
    exporter = BoundedGrpcExporter(transport, max_attempts=2)
    observer = BoundedObserver(exporter, capacity=1)

    assert observer.emit(event()) is True
    observer.close(timeout=1)

    assert transport.calls == [EVENT_ID, EVENT_ID]
    assert observer.stats.exported == 1


def test_authentication_error_is_not_retried_and_is_safe() -> None:
    transport = StatusTransport("UNAUTHENTICATED")
    exporter = BoundedGrpcExporter(transport, max_attempts=3)

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    assert transport.calls == 1
    assert raised.value.code == "INGEST_AUTHENTICATION_FAILED"
    assert raised.value.category == "authentication"
    assert raised.value.retryable is False
    assert "secret" not in str(raised.value).lower()


def test_unavailable_error_retries_with_the_configured_backoff() -> None:
    transport = StatusTransport("UNAVAILABLE")
    delays: list[float] = []
    exporter = BoundedGrpcExporter(transport, max_attempts=3, backoff=lambda attempt: delays.append(attempt) or 0)

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    assert transport.calls == 3
    assert delays == [1, 2]
    assert raised.value.code == "INGEST_UNAVAILABLE"
    assert raised.value.retryable is True


def test_protocol_violation_is_not_retried() -> None:
    exporter = BoundedGrpcExporter(InvalidResponseTransport(), max_attempts=3)

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    assert raised.value.code == "INGEST_PROTOCOL_VIOLATION"
    assert raised.value.retryable is False


def test_unrecognized_grpc_status_is_redacted_from_errors_and_diagnostics() -> None:
    exporter = BoundedGrpcExporter(StatusTransport("password=secret"), max_attempts=1)

    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    report = DiagnosticReporter().capture(raised.value, component="sdk.grpc_exporter")
    assert raised.value.code == "INGEST_REQUEST_REJECTED"
    assert report.evidence["grpc_status"] == "UNRECOGNIZED"
    assert "secret" not in str(report.to_ai_payload()).lower()


def test_circuit_breaker_opens_after_repeated_terminal_delivery_failures() -> None:
    transport = StatusTransport("UNAVAILABLE")
    exporter = BoundedGrpcExporter(transport, max_attempts=1, failure_threshold=2)

    for _ in range(2):
        with pytest.raises(ExportDeliveryError, match="unavailable"):
            exporter.write(event())
    with pytest.raises(ExportDeliveryError) as raised:
        exporter.write(event())

    assert transport.calls == 2
    assert raised.value.code == "INGEST_CIRCUIT_OPEN"


def test_observer_preserves_typed_grpc_failure_in_diagnostics() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(BoundedGrpcExporter(StatusTransport("UNAUTHENTICATED"), max_attempts=1), diagnostic_reporter=reporter)

    assert observer.emit(event())
    observer.close(timeout=1)

    assert observer.stats.failed == 1
    assert reporter.reports[0].failure["code"] == "INGEST_AUTHENTICATION_FAILED"
    assert reporter.reports[0].correlation == {"event_id": EVENT_ID, "trace_id": "trace-1", "run_id": "run-1"}
