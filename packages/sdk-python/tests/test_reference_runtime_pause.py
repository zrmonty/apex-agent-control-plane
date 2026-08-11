"""Tests for ``ReferenceReasonActLoop``'s cooperative ``pause``/``resume``
enactment.

Split out of a larger ``test_reference_runtime.py`` -- see that file for
basic turn-loop mechanics, and ``test_reference_runtime_stop.py`` /
``_budget.py`` / ``_inject.py`` / ``_hold.py`` for the other cooperative
control actions.

``ScriptedPoller`` and ``_drive`` -- which model a runtime driven across many
``run()`` calls, one scripted batch of commands per poll -- live in
``conftest.py``: every enactment suite except ``test_reference_runtime_stop.py``
needs them.
"""

from apex_sdk import BoundedObserver, PollResult
from conftest import Sink, _command, _drive, _loop, _stop_command, ScriptedPoller


def test_a_pause_halts_the_tool_and_a_resume_restores_it_on_the_same_turn():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [
            (),  # turn 1: nothing pending
            (_command("pause", command_id="cmd-pause-1", reason_code="operator.request"),),
            (),  # turn 3: still paused, nothing new
            (_command("resume", command_id="cmd-resume-1"),),
            (),  # turn 5: normal again
        ]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 5, calls)
    finally:
        observer.close(timeout=1)

    assert [terminal["status"] for terminal in terminals] == [
        "completed",
        "paused",
        "paused",
        "resumed",
        "completed",
    ]
    # The property that matters: the tool ran on turns 1, 4 and 5 and on
    # neither paused turn. A pause that lets one more tool call through has
    # not paused anything.
    assert len(calls) == 3
    assert terminals[1]["control_command_id"] == "cmd-pause-1"
    assert terminals[2]["control_command_id"] == "cmd-pause-1"
    assert terminals[3]["control_command_id"] == "cmd-resume-1"
    assert "control_command_id" not in terminals[4]

    control_events = [event for event in sink.events if event["type"] == "control"]
    # Exactly one `control` event per operator command, not one per paused
    # turn: the acknowledgement is of the command, and the command arrived
    # once. Turn 3 stays paused and emits only its terminal event.
    assert [event["data"]["action"] for event in control_events] == ["pause", "resume"]
    assert control_events[0]["data"]["reason_code"] == "operator.request"
    assert control_events[0]["actor"] == {"type": "agent", "id": "agent"}
    assert control_events[1]["data"]["reason_code"] is None


def test_a_paused_turn_emits_no_tool_or_message_event():
    sink = Sink()
    observer = BoundedObserver(sink)
    poller = ScriptedPoller([(_command("pause", command_id="cmd-pause-1"),)])
    try:
        events = _loop(observer, control=poller).run("prompt-ref", tool=lambda value: "result")
    finally:
        observer.close(timeout=1)
    assert [event["type"] for event in events] == ["turn_start", "llm", "control", "turn_end"]


def test_a_redelivered_pause_does_not_re_announce_itself_every_turn():
    # At-least-once delivery means the gateway re-serves the same `pause`
    # after its redelivery window. The agent must stay paused and must not
    # emit a second `control` event for a command it already enacted.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    pause = _command("pause", command_id="cmd-pause-1")
    poller = ScriptedPoller([(pause,), (pause,), (pause,)])
    try:
        terminals = _drive(_loop(observer, control=poller), 3, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["paused"] * 3
    assert calls == []
    assert [
        event["data"]["action"] for event in sink.events if event["type"] == "control"
    ] == ["pause"]


def test_a_second_pause_while_already_paused_is_a_safe_no_op():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [
            (_command("pause", command_id="cmd-pause-1"),),
            (_command("pause", command_id="cmd-pause-2"),),
            (_command("resume", command_id="cmd-resume-1"),),
        ]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 3, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["paused", "paused", "resumed"]
    # The agent stays attributed to the pause that actually paused it, and a
    # single resume is enough to release it -- a second pause must not require
    # a second resume.
    assert terminals[1]["control_command_id"] == "cmd-pause-1"
    assert len(calls) == 1


def test_a_resume_for_an_agent_that_was_never_paused_is_a_safe_no_op():
    # An operator who is not sure whether an agent is paused must be able to
    # send `resume` without risking an error path or a spurious trace entry.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_command("resume", command_id="cmd-resume-1"),)])
    try:
        terminals = _drive(_loop(observer, control=poller), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "completed"}
    assert calls == ["reference-input"]
    assert [event for event in sink.events if event["type"] == "control"] == []


def test_a_redelivered_resume_cannot_undo_a_later_pause():
    # The failure this guards against: resume R is enacted, pause P is issued
    # afterwards, and the gateway's redelivery window then re-serves R.
    # Without per-command idempotency the agent would silently un-pause.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    resume = _command("resume", command_id="cmd-resume-1")
    poller = ScriptedPoller(
        [
            (_command("pause", command_id="cmd-pause-1"),),
            (resume,),
            (_command("pause", command_id="cmd-pause-2"),),
            (resume,),
        ]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 4, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == [
        "paused",
        "resumed",
        "paused",
        "paused",
    ]
    assert len(calls) == 1


def test_a_stop_wins_over_a_pause_delivered_in_the_same_batch():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [(_command("pause", command_id="cmd-pause-1"), _stop_command(command_id="cmd-stop-1"))]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "stopped", "control_command_id": "cmd-stop-1"}
    assert [
        event["data"]["action"] for event in sink.events if event["type"] == "control"
    ] == ["stop"]
    assert calls == []


def test_pause_and_resume_in_one_batch_apply_in_delivery_order():
    # The gateway returns commands oldest-first, so the operator's last
    # instruction is the one that holds. Both orderings are asserted so the
    # rule is not accidentally "whichever the loop happens to see last".
    for order, expected in ((("pause", "resume"), "completed"), (("resume", "pause"), "paused")):
        sink = Sink()
        observer = BoundedObserver(sink)
        calls = []
        batch = tuple(_command(action, command_id=f"cmd-{action}-1") for action in order)
        try:
            terminals = _drive(_loop(observer, control=ScriptedPoller([batch])), 1, calls)
        finally:
            observer.close(timeout=1)
        assert terminals[0]["status"] == expected, order


def test_a_pause_survives_a_control_channel_failure():
    # Fail-open applies to *discovering* commands, not to forgetting the ones
    # already enacted. An unreachable gateway is not a reason to start running
    # again.
    class _FlakyPoller:
        def __init__(self):
            self.polls = 0

        def poll(self, *, max_commands=0):
            self.polls += 1
            if self.polls == 1:
                return PollResult(
                    commands=(_command("pause", command_id="cmd-pause-1"),),
                    agent_id="agent",
                    min_poll_interval_seconds=1,
                )
            raise RuntimeError("control gateway unreachable")

        def close(self):
            return None

    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    try:
        terminals = _drive(_loop(observer, control=_FlakyPoller()), 2, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["paused", "paused"]
    assert calls == []


def test_a_pause_with_an_out_of_grammar_reason_code_still_pauses_the_run():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [(_command("pause", command_id="cmd-pause-1", reason_code="not a safe identifier"),)]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0]["status"] == "paused"
    assert calls == []
    control_event = next(event for event in sink.events if event["type"] == "control")
    assert control_event["data"]["reason_code"] is None


def test_a_resume_carrying_a_reason_code_still_resumes_the_run():
    # `ControlCommand` refuses a reason_code on resume, but the gateway's own
    # validation does not, so one can reach a runtime. It must not be able to
    # make the resume un-enactable.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [
            (_command("pause", command_id="cmd-pause-1"),),
            (_command("resume", command_id="cmd-resume-1", reason_code="operator.request"),),
        ]
    )
    try:
        terminals = _drive(_loop(observer, control=poller), 2, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["paused", "resumed"]
    assert calls == ["reference-input"]


def test_a_command_with_no_identifier_is_never_enacted():
    # `command_id` is what makes enactment idempotent. A command that arrives
    # without one cannot be de-duplicated, so it is refused rather than
    # enacted once and then re-enacted on every redelivery.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_command("pause", command_id=""),)])
    try:
        terminals = _drive(_loop(observer, control=poller), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "completed"}
    assert calls == ["reference-input"]
