import json

import pytest

from apex_sdk import BoundedObserver, JsonlSink, ReferenceReasonActLoop
from apex_sdk.exporter import BoundedGrpcExporter, GrpcStatusError, InMemoryIdempotentIngest


def _loop(observer: BoundedObserver) -> ReferenceReasonActLoop:
    return ReferenceReasonActLoop(
        observer,
        agent_id="phase0-agent",
        scope={"workspace_id": "local", "namespace_id": "demo", "agent_group_ids": []},
        version={"agent_code": "test", "prompt": "test", "model": "reference"},
    )


def test_replay_of_same_event_id_is_acknowledged_as_duplicate() -> None:
    transport = InMemoryIdempotentIngest()
    exporter = BoundedGrpcExporter(transport, max_attempts=1)
    sink_events: list[dict] = []

    class Sink:
        def write(self, event: dict) -> None:
            sink_events.append(event)

        def close(self) -> None:
            return

    observer = BoundedObserver(Sink())
    events = _loop(observer).run("replay-safe")
    observer.close(timeout=2)
    exporter.write(events[0])
    exporter.write(events[0])

    assert exporter.stats["delivered"] == 1
    assert exporter.stats["duplicates"] == 1
    assert len(transport.events) == 1


def test_jsonl_trace_survives_sink_reopen_after_a_simulated_restart(tmp_path) -> None:
    output = tmp_path / "events.jsonl"
    first = JsonlSink(output, base_dir=tmp_path)
    observer = BoundedObserver(first)
    events = _loop(observer).run("restart-safe")
    observer.close(timeout=2)

    reopened = JsonlSink(output, base_dir=tmp_path)
    reopened.write(events[-1])
    reopened.close()
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

    assert len(records) == len(events) + 1
    assert records[-1]["event_id"] == events[-1]["event_id"]


def test_replay_harness_rejects_same_event_id_with_changed_payload() -> None:
    transport = InMemoryIdempotentIngest()
    observer = BoundedObserver(type("Sink", (), {"write": lambda self, event: None, "close": lambda self: None})())
    event = _loop(observer).run("original")[0]
    observer.close(timeout=2)
    transport.ingest(event, event_id=event["event_id"])
    changed = dict(event)
    changed["data"] = {"changed": True}

    with pytest.raises(GrpcStatusError) as raised:
        transport.ingest(changed, event_id=event["event_id"])
    assert raised.value.status == "INVALID_ARGUMENT"
