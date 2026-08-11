"""Tests for ``ReferenceReasonActLoop``'s cooperative ``stop`` enactment.

Split out of a larger ``test_reference_runtime.py`` -- see that file for
basic turn-loop mechanics, and ``test_reference_runtime_pause.py`` /
``_budget.py`` / ``_inject.py`` / ``_hold.py`` for the other cooperative
control actions.

The ``Sink`` test sink and the ``_loop``/``InMemoryControlPoller``-adjacent
test-data builders this file needs live in ``conftest.py``.
"""

from apex_sdk import BoundedObserver, InMemoryControlPoller
from conftest import Sink, _command, _loop, _stop_command


def test_a_pending_stop_halts_the_run_before_the_tool_executes():
    sink = Sink()
    observer = BoundedObserver(sink)
    executed = []
    poller = InMemoryControlPoller([_stop_command()], agent_id="agent")
    try:
        events = _loop(observer, control=poller).run(
            "prompt-ref", tool=lambda value: executed.append(value) or "result"
        )
    finally:
        observer.close(timeout=1)

    # The tool never ran. That is the property that matters: a `stop` observed
    # after the side effect has stopped nothing.
    assert executed == []
    assert [event["type"] for event in events] == ["turn_start", "llm", "control", "turn_end"]
    control_event = events[2]
    assert control_event["data"]["action"] == "stop"
    assert control_event["data"]["enforcement"] == "cooperative"
    assert control_event["data"]["reason_code"] == "operator.request"
    # The agent's own actor, distinguishable in the trace from the operator's
    # control event that carries actor type "user".
    assert control_event["actor"] == {"type": "agent", "id": "agent"}
    assert events[3]["data"] == {
        "status": "stopped",
        "control_command_id": "018f0000-0000-7000-8000-000000000001",
    }
    assert poller.polls == 1
    assert poller.acknowledgements == ["018f0000-0000-7000-8000-000000000001"]


def test_an_empty_control_channel_leaves_the_run_untouched():
    sink = Sink()
    observer = BoundedObserver(sink)
    poller = InMemoryControlPoller([], agent_id="agent")
    try:
        events = _loop(observer, control=poller).run("prompt-ref", tool=lambda value: "result")
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "tool", "message", "turn_end"]
    assert events[-1]["data"] == {"status": "completed"}
    assert poller.polls == 1


def test_an_action_the_runtime_does_not_recognise_is_inert():
    # A gateway newer than this client can deliver an action it decodes as
    # "unspecified". A runtime only enacts what it recognises.
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        events = _loop(
            observer,
            control=InMemoryControlPoller(
                [_command("unspecified", command_id="cmd-from-the-future")]
            ),
        ).run("prompt-ref", tool=lambda value: "result")
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "tool", "message", "turn_end"]


def test_a_stop_with_an_out_of_grammar_reason_code_still_halts_the_run():
    # The reason code is operator-supplied text. It must never be able to make
    # a `stop` un-enactable by failing event validation.
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        events = _loop(
            observer, control=InMemoryControlPoller([_stop_command(reason_code="not a safe identifier")])
        ).run("prompt-ref", tool=lambda value: "result")
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "control", "turn_end"]
    assert events[2]["data"]["reason_code"] is None


def test_a_control_channel_failure_records_an_error_and_does_not_halt_the_run():
    # Fail-open, deliberately: an unreachable out-of-band channel must not
    # become a fleet-wide outage. The `error` event is what keeps the trace
    # honest about the check not having happened.
    class _BrokenPoller:
        def poll(self, *, max_commands=0):
            raise RuntimeError("control gateway unreachable")

        def close(self):
            return None

    sink = Sink()
    observer = BoundedObserver(sink)
    executed = []
    try:
        events = _loop(observer, control=_BrokenPoller()).run(
            "prompt-ref", tool=lambda value: executed.append(value) or "result"
        )
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "error", "tool", "message", "turn_end"]
    assert events[2]["data"]["code"] == "CONTROL_POLL_UNAVAILABLE"
    assert executed == ["reference-input"]


def test_a_run_with_no_tool_step_does_not_poll_the_control_channel():
    # One checkpoint, in one place. A run with no side effect to gate has
    # nothing to check, and polling anyway would spend the gateway's
    # per-agent budget for no benefit.
    sink = Sink()
    observer = BoundedObserver(sink)
    poller = InMemoryControlPoller([_stop_command()])
    try:
        events = _loop(observer, control=poller).run("prompt-ref")
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "turn_end"]
    assert poller.polls == 0
