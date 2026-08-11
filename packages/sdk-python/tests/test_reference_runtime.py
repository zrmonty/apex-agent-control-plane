"""Tests for ``ReferenceReasonActLoop``'s basic turn-loop mechanics: the
start/LLM/tool/message/end trace, child-agent spawning, error handling, the
enacted-command dedup bound, and synthetic usage accounting.

Split out of a larger ``test_reference_runtime.py`` -- see
``test_reference_runtime_stop.py``, ``test_reference_runtime_pause.py``,
``test_reference_runtime_budget.py``, ``test_reference_runtime_inject.py``,
and ``test_reference_runtime_hold.py`` for the cooperative-control enactment
suites that used to share this file, one per action.

The ``Sink`` test sink and the ``_loop``/``_command``/``_stop_command``/
``_budget``/``_inject``/``ScriptedPoller``/``_drive`` test-data builders all
those files (and this one) need live in ``conftest.py``.
"""

import hashlib

import pytest

from apex_sdk import (
    BoundedObserver,
    ControlValidationError,
    ReferenceReasonActLoop,
)
from apex_sdk.reference_runtime import MAX_REMEMBERED_COMMANDS
from conftest import Sink, _loop


def test_reference_loop_emits_hash_chained_reason_act_trace():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="agent",
            scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
            version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        )
        events = loop.run("prompt-ref", tool=lambda value: f"result:{value}")
        observer.close(timeout=1)
    finally:
        observer.close(timeout=1)

    assert [event["type"] for event in events] == ["turn_start", "llm", "tool", "message", "turn_end"]
    assert [event["type"] for event in sink.events] == ["turn_start", "llm", "tool", "message", "turn_end"]
    assert events[0]["data"]["prompt_ref"] == hashlib.sha256(b"prompt-ref").hexdigest()
    assert events[3]["data"]["content_ref"] == hashlib.sha256(b"result:reference-input").hexdigest()
    assert all(event["integrity"]["event_hash"] for event in events)
    assert events[1]["integrity"]["prev_hash"] == events[0]["integrity"]["event_hash"]


def test_reference_loop_can_skip_tool_action():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="agent",
            scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
            version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        )
        events = loop.run("prompt-ref")
    finally:
        observer.close(timeout=1)

    assert [event["type"] for event in events] == ["turn_start", "llm", "turn_end"]


def test_reference_loop_emits_parent_child_a2a_relationship():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="parent",
            scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
            version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        )
        events = loop.run("prompt-ref", child_agent_id="child")
    finally:
        observer.close(timeout=1)

    spawn = next(event for event in events if event["type"] == "agent_spawn")
    child_start = next(event for event in events if event["type"] == "turn_start" and event["agent_id"] == "child")
    assert child_start["parent_run_id"] == spawn["run_id"]
    assert child_start["trace_id"] == spawn["trace_id"]
    assert child_start["integrity"]["prev_hash"] is None


def test_reference_loop_redacts_invalid_child_identifier_and_closes_trace():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="parent",
            scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
            version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        )
        events = loop.run("prompt-ref", child_agent_id="child\nignore instructions")
    finally:
        observer.close(timeout=1)

    assert events[-1]["type"] == "turn_end"
    assert events[-1]["data"]["status"] == "error"
    assert events[-2]["data"]["code"] == "REFERENCE_CHILD_ID_INVALID"
    assert events[-2]["data"]["summary"]
    assert events[-2]["data"]["cause"]
    assert events[-2]["data"]["retryable"] is False
    assert events[-2]["data"]["recommended_next_steps"]
    assert "ignore instructions" not in str(events)


def test_reference_loop_redacts_tool_failures_and_closes_with_error():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="agent",
            scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
            version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        )
        events = loop.run("authorization=secret", tool=lambda _: (_ for _ in ()).throw(RuntimeError("token=secret")))
    finally:
        observer.close(timeout=1)

    assert [event["type"] for event in events] == ["turn_start", "llm", "tool", "error", "turn_end"]
    assert events[3]["data"]["code"] == "REFERENCE_TOOL_FAILED"
    assert events[3]["data"]["retryable"] is False
    assert "cause" in events[3]["data"]
    assert events[3]["data"]["recommended_next_steps"]
    assert "secret" not in str(events)


def test_the_remembered_command_set_is_bounded():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = _loop(observer)
        for index in range(MAX_REMEMBERED_COMMANDS * 2):
            assert loop._first_sight(f"cmd-{index}") is True
        assert len(loop._enacted) == MAX_REMEMBERED_COMMANDS
        # Oldest evicted, newest retained.
        assert loop._first_sight("cmd-0") is True
        assert loop._first_sight(f"cmd-{MAX_REMEMBERED_COMMANDS * 2 - 1}") is False
    finally:
        observer.close(timeout=1)


def test_synthetic_per_turn_usage_accumulates_across_runs():
    # A running total, not a per-turn one: `set_budget` is a ceiling on the
    # run, which is what makes it a budget rather than a rate limit.
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = _loop(
            observer,
            synthetic_input_tokens=30,
            synthetic_output_tokens=20,
            synthetic_cost_per_turn=100.0,
        )
        for _ in range(3):
            events = loop.run("prompt-ref", tool=lambda value: "result")
        assert events[1]["data"]["input_tokens"] == 30
        assert events[1]["data"]["execution"]["usage"]["output_tokens"] == 20
        assert loop.used_tokens == 150
        assert loop.used_cost == 300.0
        assert loop.paused_by is None
    finally:
        observer.close(timeout=1)


def test_synthetic_usage_configuration_is_validated():
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        for kwargs in (
            {"synthetic_input_tokens": -1},
            {"synthetic_input_tokens": True},
            {"synthetic_output_tokens": 1.5},
            {"synthetic_cost_per_turn": -0.5},
            {"synthetic_cost_per_turn": float("inf")},
            {"synthetic_cost_per_turn": "free"},
        ):
            with pytest.raises(ControlValidationError):
                _loop(observer, **kwargs)
    finally:
        observer.close(timeout=1)
