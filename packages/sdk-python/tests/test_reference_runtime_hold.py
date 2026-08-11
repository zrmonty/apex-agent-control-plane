"""Tests for ``ReferenceReasonActLoop``'s cooperative ``resolve_hold``
enactment.

Split out of a larger ``test_reference_runtime.py`` -- see that file for
basic turn-loop mechanics, and ``test_reference_runtime_stop.py`` /
``_pause.py`` / ``_budget.py`` / ``_inject.py`` for the other cooperative
control actions. Two inject-themed tests that sat physically at the end of
the original file, right after this section, moved to
``test_reference_runtime_inject.py`` instead -- see that file's docstring.

``_resolve_hold`` is local to this file: nothing else in the split needs it.
"""

import pytest

from apex_sdk import BoundedObserver
from conftest import Sink, ScriptedPoller, _command, _drive, _loop, _stop_command


def _resolve_hold(hold_token, decision, *, command_id="cmd-resolve-1", reason=None, reason_code=None):
    return _command(
        "resolve_hold",
        command_id=command_id,
        reason_code=reason_code,
        parameters={"hold_token": hold_token, "decision": decision, "reason": reason},
    )


def test_enter_hold_generates_a_fresh_token_and_the_turn_does_not_run_the_tool():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer, control=ScriptedPoller([()]))
    try:
        token = loop.enter_hold()
        assert token
        assert loop.held_token == token
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "held", "hold_token": token}
    assert calls == []
    # Entering a hold is the agent's own decision, not an operator command --
    # unlike stop/pause/resume/inject/set_budget, there is nothing to echo
    # into the trace as a `control` event until it is resolved.
    assert [event for event in sink.events if event["type"] == "control"] == []


def test_enter_hold_while_already_held_replaces_the_previous_token():
    sink = Sink()
    observer = BoundedObserver(sink)
    loop = _loop(observer)
    try:
        first = loop.enter_hold()
        second = loop.enter_hold()
    finally:
        observer.close(timeout=1)
    assert first != second
    assert loop.held_token == second


def test_an_approved_resolve_hold_unblocks_the_held_call_and_the_tool_runs_that_turn():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller(
            [(_resolve_hold(token, "approved", reason="looks legitimate"),)]
        )
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    # Unblocked: the loop is no longer waiting, and the tool ran on the same
    # turn the decision arrived, the same way a `resume` releases a `pause`
    # without needing an extra turn.
    assert loop.held_token is None
    assert terminals[0] == {"status": "completed", "control_command_id": "cmd-resolve-1"}
    assert calls == ["reference-input"]
    control_event = next(event for event in sink.events if event["type"] == "control")
    assert control_event["data"]["action"] == "resolve_hold"
    assert control_event["data"]["parameters"] == {
        "hold_token": token,
        "decision": "approved",
        "reason": "looks legitimate",
    }
    assert control_event["actor"] == {"type": "agent", "id": "agent"}


def test_a_denied_resolve_hold_ends_the_turn_without_running_the_tool():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller(
            [(_resolve_hold(token, "denied", reason="not authorized"),), ()]
        )
        terminals = _drive(loop, 2, calls)
    finally:
        observer.close(timeout=1)
    # Unblocked either way -- the wait ends -- but a denial does not let the
    # tool run, and it ends only this turn rather than the whole run: the
    # very next turn is ordinary again.
    assert loop.held_token is None
    assert terminals[0] == {
        "status": "held_denied",
        "control_command_id": "cmd-resolve-1",
        "hold_reason": "not authorized",
    }
    assert terminals[1] == {"status": "completed"}
    assert calls == ["reference-input"]


def test_a_resolve_hold_for_a_loop_that_is_not_currently_held_is_a_safe_no_op():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_resolve_hold("some-token-nobody-is-waiting-on", "approved"),)])
    try:
        terminals = _drive(_loop(observer, control=poller), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "completed"}
    assert calls == ["reference-input"]
    assert [event for event in sink.events if event["type"] == "control"] == []


def test_a_resolve_hold_for_the_wrong_token_while_held_is_a_safe_no_op():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller([(_resolve_hold("a-different-hold-entirely", "approved"),)])
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    # Still held: the wrong identifier resolved nothing.
    assert loop.held_token == token
    assert terminals[0] == {"status": "held", "hold_token": token}
    assert calls == []
    assert [event for event in sink.events if event["type"] == "control"] == []


def test_a_redelivered_resolve_hold_does_not_re_apply_after_the_hold_is_resolved():
    # At-least-once delivery means the gateway can re-serve the same
    # `resolve_hold` after its redelivery window. By then `held_token` is
    # already `None`, so the redelivered command matches nothing -- the same
    # idempotence discipline `stop` already has for an already-stopped loop.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        first_token = loop.enter_hold()
        resolve = _resolve_hold(first_token, "approved")
        loop._control = ScriptedPoller([(resolve,), (resolve,)])
        terminals = _drive(loop, 1, calls)
        second_token = loop.enter_hold()
        terminals += _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "completed", "control_command_id": "cmd-resolve-1"}
    # The redelivered resolve_hold names a token that no longer matches
    # anything this loop is waiting on, so the second hold stays held.
    assert terminals[1] == {"status": "held", "hold_token": second_token}
    assert calls == ["reference-input"]
    control_events = [event for event in sink.events if event["type"] == "control"]
    assert len(control_events) == 1, "a redelivered resolve_hold must not be re-enacted"


def test_a_stop_wins_over_a_resolve_hold_delivered_in_the_same_batch():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller(
            [(_resolve_hold(token, "approved"), _stop_command(command_id="cmd-stop-1"))]
        )
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "stopped", "control_command_id": "cmd-stop-1"}
    # `stop` wins over everything in the batch, so the hold is never resolved.
    assert loop.held_token == token
    assert calls == []
    assert [
        event["data"]["action"] for event in sink.events if event["type"] == "control"
    ] == ["stop"]


@pytest.mark.parametrize(
    "parameters",
    [
        {"hold_token": None, "decision": "approved", "reason": None},
        {"hold_token": "", "decision": "approved", "reason": None},
        {"decision": "approved", "reason": None},
        {},
    ],
)
def test_a_resolve_hold_with_a_malformed_hold_token_is_a_safe_no_op(parameters):
    # None of these can ever equal the token this loop actually generated, so
    # each is indistinguishable from "wrong identifier" -- a safe no-op that
    # leaves the hold in force, not an error.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller(
            [(_command("resolve_hold", command_id="cmd-bad-resolve", parameters=parameters),)]
        )
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    assert loop.held_token == token
    assert terminals[0] == {"status": "held", "hold_token": token}
    assert calls == []
    assert [event for event in sink.events if event["type"] == "control"] == []


def test_an_invalid_resolve_hold_decision_emits_an_error_and_is_refused():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = ScriptedPoller([(_resolve_hold(token, "maybe"),)])
        terminals = _drive(loop, 1, calls)
    finally:
        observer.close(timeout=1)
    assert loop.held_token == token
    assert terminals[0] == {"status": "held", "hold_token": token}
    assert calls == []
    errors = [event for event in sink.events if event["type"] == "error"]
    assert [event["data"]["code"] for event in errors] == [
        "REFERENCE_RESOLVE_HOLD_PARAMETERS_INVALID"
    ]


def test_a_resolve_hold_survives_a_control_channel_failure():
    # Fail-open applies to *discovering* a resolution, not to forgetting the
    # hold already in force. An unreachable gateway is not a reason to run
    # the held call.
    class _FlakyPoller:
        def __init__(self):
            self.polls = 0

        def poll(self, *, max_commands=0):
            self.polls += 1
            raise RuntimeError("control gateway unreachable")

        def close(self):
            return None

    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    loop = _loop(observer)
    try:
        token = loop.enter_hold()
        loop._control = _FlakyPoller()
        terminals = _drive(loop, 2, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["held", "held"]
    assert loop.held_token == token
    assert calls == []
    assert [event for event in sink.events if event["type"] == "control"] == []
