import json
from threading import Event
from time import monotonic

import pytest

from apex_sdk.diagnostics import DiagnosticReporter, EmergencySpool
from apex_sdk import ConfigurationError, EventBuilder
from apex_sdk.observer import BoundedObserver, JsonlSink, MAX_JSONL_FILE_BYTES


def valid_event(event_id: str) -> dict:
    return EventBuilder(agent_id="agent", run_id="run-1", trace_id="trace-1", scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []}, actor={"type": "agent", "id": "agent"}, version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"}).build("turn_start", {}, event_id=event_id)


class BlockingSink:
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()
        self.events: list[dict] = []

    def write(self, event: dict) -> None:
        self.started.set()
        self.release.wait(timeout=2)
        self.events.append(event)

    def close(self) -> None:
        pass


def test_jsonl_sink_rejects_existing_file_over_storage_limit(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    with path.open("wb") as file:
        file.truncate(MAX_JSONL_FILE_BYTES + 1)
    with pytest.raises(ConfigurationError, match="storage limit"):
        JsonlSink(path, base_dir=tmp_path)


class FailingSink:
    def write(self, event: dict) -> None:
        raise OSError("credential=secret")

    def close(self) -> None:
        pass


class FailingReporter:
    def capture(self, error, *, component: str) -> None:
        raise RuntimeError("token=secret")


class CloseFailingSink:
    def write(self, event: dict) -> None:
        pass

    def close(self) -> None:
        raise OSError("password=secret")


class UncopyableEvent(dict):
    def __deepcopy__(self, memo):
        raise RuntimeError("copy blocked")


class HostileLookupEvent(dict):
    def get(self, key, default=None):
        raise RuntimeError("lookup blocked")


def test_emit_is_non_blocking_when_sink_is_slow() -> None:
    sink = BlockingSink()
    observer = BoundedObserver(sink, capacity=1)
    try:
        started = monotonic()
        accepted = observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000001"))
        elapsed = monotonic() - started
        assert accepted is True
        assert elapsed < 0.05
        assert sink.started.wait(timeout=1)
    finally:
        sink.release.set()
        observer.close(timeout=1)


def test_bounded_queue_drops_newest_event_and_records_it() -> None:
    sink = BlockingSink()
    observer = BoundedObserver(sink, capacity=1)
    try:
        assert observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000001")) is True
        assert sink.started.wait(timeout=1)
        assert observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000002")) is True
        assert observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000003")) is False
        assert observer.stats.dropped == 1
        assert observer.stats.accepted == 2
    finally:
        sink.release.set()
        observer.close(timeout=1)


def test_close_drains_accepted_events() -> None:
    sink = BlockingSink()
    observer = BoundedObserver(sink, capacity=2)
    assert observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000001")) is True
    assert sink.started.wait(timeout=1)
    assert observer.emit(valid_event("018f5c91-2d88-7c00-8000-000000000002")) is True
    sink.release.set()
    observer.close(timeout=1)
    assert [event["event_id"] for event in sink.events] == [
        "018f5c91-2d88-7c00-8000-000000000001",
        "018f5c91-2d88-7c00-8000-000000000002",
    ]
    assert observer.stats.exported == 2


def test_jsonl_sink_persists_one_event_per_line(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlSink(path, base_dir=tmp_path)
    first = valid_event("018f5c91-2d88-7c00-8000-000000000001")
    second = valid_event("018f5c91-2d88-7c00-8000-000000000002")
    sink.write(first)
    sink.write(second)
    sink.close()
    assert [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] == [
        first,
        second,
    ]


def test_jsonl_sink_rejects_a_path_outside_its_trusted_directory(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="base directory"):
        JsonlSink(tmp_path.parent / "outside.jsonl", base_dir=tmp_path)


def test_emit_after_close_is_rejected() -> None:
    observer = BoundedObserver(BlockingSink(), capacity=1)
    observer.close(timeout=1)
    assert observer.emit({"event_id": "late"}) is False


def test_emit_rejects_invalid_events_before_enqueueing() -> None:
    observer = BoundedObserver(BlockingSink(), capacity=1)
    try:
        assert observer.emit({"event_id": "not-a-canonical-event"}) is False
        assert observer.stats.accepted == 0
        assert observer.stats.dropped == 1
    finally:
        observer.close(timeout=1)


def test_invalid_event_is_reported_without_leaking_payload() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(BlockingSink(), capacity=1, diagnostic_reporter=reporter)
    try:
        assert observer.emit({"event_id": "not-a-canonical-event"}) is False
        assert reporter.reports[0].failure["code"] == "EVENT_VALIDATION_FAILED"
    finally:
        observer.close(timeout=1)


def test_uncopyable_event_is_dropped_with_safe_diagnostic() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(BlockingSink(), capacity=1, diagnostic_reporter=reporter)
    try:
        event = UncopyableEvent(valid_event("018f5c91-2d88-7c00-8000-000000000004"))
        assert observer.emit(event) is False
        assert reporter.reports[0].failure["code"] == "OBSERVER_EXPORT_FAILED"
    finally:
        observer.close(timeout=1)


def test_hostile_event_lookup_cannot_escape_diagnostic_boundary() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(BlockingSink(), capacity=1, diagnostic_reporter=reporter)
    try:
        assert observer.emit(HostileLookupEvent({"event_id": "invalid"})) is False
        assert observer.stats.dropped == 1
    finally:
        observer.close(timeout=1)


def test_emit_snapshots_events_before_background_delivery() -> None:
    sink = BlockingSink()
    observer = BoundedObserver(sink, capacity=1)
    event = valid_event("018f5c91-2d88-7c00-8000-000000000001")
    try:
        assert observer.emit(event) is True
        assert sink.started.wait(timeout=1)
        original_hash = event["integrity"]["event_hash"]
        event["data"]["mutated_after_emit"] = True
        event["integrity"]["event_hash"] = "0" * 64
        sink.release.set()
        observer.close(timeout=1)
        assert sink.events[0]["integrity"]["event_hash"] == original_hash
        assert "mutated_after_emit" not in sink.events[0]["data"]
    finally:
        sink.release.set()
        observer.close(timeout=1)


@pytest.mark.parametrize("capacity", [0, -1, "1", None, True])
def test_capacity_must_be_positive(capacity: object) -> None:
    with pytest.raises(ConfigurationError, match="at least one"):
        BoundedObserver(BlockingSink(), capacity=capacity)  # type: ignore[arg-type]


def test_close_is_idempotent() -> None:
    observer = BoundedObserver(BlockingSink(), capacity=1)
    observer.close(timeout=1)
    observer.close(timeout=1)


def test_sink_failure_is_recorded_without_crashing_the_worker() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(FailingSink(), diagnostic_reporter=reporter)
    event_id = "018f5c91-2d88-7c00-8000-000000000001"
    assert observer.emit(valid_event(event_id))
    observer.close(timeout=1)

    assert observer.stats.failed == 1
    assert reporter.reports[0].failure["code"] == "OBSERVER_EXPORT_FAILED"
    assert reporter.reports[0].correlation == {"event_id": event_id, "trace_id": "trace-1", "run_id": "run-1"}
    assert "secret" not in str(reporter.reports[0].evidence).lower()


def test_reporter_failure_writes_a_minimal_redacted_emergency_record(tmp_path) -> None:
    path = tmp_path / "emergency.jsonl"
    observer = BoundedObserver(FailingSink(), diagnostic_reporter=FailingReporter(), emergency_spool=EmergencySpool(path, base_dir=tmp_path))
    event_id = "018f5c91-2d88-7c00-8000-000000000001"
    assert observer.emit(valid_event(event_id))
    observer.close(timeout=1)

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["code"] == "OBSERVER_EXPORT_FAILED"
    assert record["correlation"] == {"event_id": event_id, "trace_id": "trace-1", "run_id": "run-1"}
    assert "secret" not in str(record).lower()


def test_sink_close_failure_is_reported_without_raising_to_the_agent() -> None:
    reporter = DiagnosticReporter()
    observer = BoundedObserver(CloseFailingSink(), diagnostic_reporter=reporter)
    observer.close(timeout=1)

    assert observer.stats.failed == 1
    assert reporter.reports[0].failure["code"] == "OBSERVER_EXPORT_FAILED"


def test_emergency_spool_rejects_paths_outside_its_configured_directory(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="base directory"):
        EmergencySpool(tmp_path.parent / "outside.jsonl", base_dir=tmp_path)
