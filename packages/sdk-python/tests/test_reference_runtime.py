import hashlib

import pytest

from apex_sdk import (
    BoundedObserver,
    ControlValidationError,
    InMemoryControlPoller,
    PendingControlCommand,
    PollResult,
    ReferenceReasonActLoop,
)
from apex_sdk.reference_runtime import MAX_REMEMBERED_COMMANDS


class Sink:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)

    def close(self):
        pass


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


# --- cooperative stop enactment -------------------------------------------


def _loop(observer, control=None, **kwargs):
    return ReferenceReasonActLoop(
        observer,
        agent_id="agent",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        control=control,
        **kwargs,
    )


def _command(action, *, command_id, reason_code=None, parameters=None):
    return PendingControlCommand(
        command_id=command_id,
        workspace_id="acme",
        namespace_id="prod",
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        action=action,
        reason_code=reason_code,
        issued_at="2026-08-08T00:00:00.000000Z",
        delivery_attempt=1,
        parameters=dict(parameters or {}),
    )


def _budget(limit, *, command_id="cmd-budget-1", kind="cost"):
    return _command(
        "set_budget", command_id=command_id, parameters={"budget_kind": kind, "limit": limit}
    )


def _stop_command(reason_code="operator.request", command_id="018f0000-0000-7000-8000-000000000001"):
    return _command("stop", command_id=command_id, reason_code=reason_code)


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


def test_a_pending_action_this_pass_does_not_enact_is_inert():
    # `inject` is retrieved and deliberately not acted on yet. An agent that
    # silently ignores it is honest; one that pretends to have consumed it is
    # not.
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        events = _loop(
            observer,
            control=InMemoryControlPoller(
                [
                    _command(
                        "inject",
                        command_id="cmd-inject",
                        parameters={"content": "hello", "content_classification": "untrusted"},
                    )
                ]
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


# --- cooperative pause / resume enactment ---------------------------------


class ScriptedPoller:
    """Returns one scripted batch of commands per poll, then nothing.

    Unlike ``InMemoryControlPoller`` this models *turns*: batch ``n`` is what
    the gateway hands back on the ``n``-th poll, which is how a runtime driven
    across many ``run()`` calls actually experiences the control channel.
    """

    def __init__(self, batches, *, agent_id="agent"):
        self._batches = list(batches)
        self._agent_id = agent_id
        self.polls = 0
        self.closed = False

    def poll(self, *, max_commands=0):
        batch = self._batches[self.polls] if self.polls < len(self._batches) else ()
        self.polls += 1
        return PollResult(
            commands=tuple(batch), agent_id=self._agent_id, min_poll_interval_seconds=1
        )

    def close(self):
        self.closed = True


def _drive(loop, turns, tool_calls):
    """Runs ``turns`` turns on one loop, recording which ones ran the tool."""
    terminals = []
    for turn in range(turns):
        events = loop.run(
            f"prompt-{turn}", tool=lambda value: tool_calls.append(value) or "result"
        )
        terminals.append(events[-1]["data"])
    return terminals


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


# --- cooperative set_budget enactment --------------------------------------


def test_a_budget_halts_the_run_on_the_turn_the_arithmetic_predicts():
    # limit 250, cost 100 per turn: turns 1 and 2 total 100 and 200 and
    # proceed; turn 3 would total 300, so it halts *before* its tool. Not
    # "eventually stopped" -- exactly turn 3.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_budget(250.0),), (), (), ()])
    try:
        loop = _loop(observer, control=poller, synthetic_cost_per_turn=100.0)
        terminals = _drive(loop, 4, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == [
        "completed",
        "completed",
        "budget_exceeded",
        "budget_exceeded",
    ]
    assert len(calls) == 2, "the tool must not run on a turn that breaches the ceiling"
    assert terminals[2]["control_command_id"] == "cmd-budget-1"
    assert loop.used_cost == 400.0
    assert loop.budget_limit == 250.0
    control_events = [event for event in sink.events if event["type"] == "control"]
    assert [event["data"]["action"] for event in control_events] == ["set_budget"]
    assert control_events[0]["data"]["parameters"] == {"budget_kind": "cost", "limit": 250.0}


def test_a_token_budget_counts_input_and_output_tokens():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_budget(120, kind="tokens"),)])
    try:
        loop = _loop(
            observer,
            control=poller,
            synthetic_input_tokens=30,
            synthetic_output_tokens=20,
        )
        terminals = _drive(loop, 4, calls)
    finally:
        observer.close(timeout=1)
    # 50 tokens a turn against a ceiling of 120: 50, 100, then 150 > 120.
    assert [terminal["status"] for terminal in terminals] == [
        "completed",
        "completed",
        "budget_exceeded",
        "budget_exceeded",
    ]
    assert len(calls) == 2
    assert loop.budget_kind == "tokens"


def test_a_budget_applies_to_usage_the_run_had_already_accumulated():
    # The conservative reading, asserted rather than described: a ceiling below
    # what the run has already spent halts it at once instead of granting a
    # fresh allowance.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(), (), (_budget(150.0),)])
    try:
        terminals = _drive(_loop(observer, control=poller, synthetic_cost_per_turn=100.0), 3, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == [
        "completed",
        "completed",
        "budget_exceeded",
    ]
    assert len(calls) == 2


def test_a_later_budget_replaces_the_ceiling_in_force():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [(_budget(150.0, command_id="cmd-budget-1"),), (_budget(1000.0, command_id="cmd-budget-2"),)]
    )
    try:
        loop = _loop(observer, control=poller, synthetic_cost_per_turn=100.0)
        terminals = _drive(loop, 3, calls)
    finally:
        observer.close(timeout=1)
    # Turn 2 would breach 150, but a wider ceiling arrived on the same poll --
    # `set_budget` is applied before the check, so it governs its own turn.
    assert [terminal["status"] for terminal in terminals] == ["completed"] * 3
    assert loop.budget_command_id == "cmd-budget-2"
    assert len(calls) == 3


def test_an_invalid_budget_is_refused_and_leaves_the_previous_ceiling_in_force():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    invalid = [
        {"budget_kind": "cost", "limit": float("nan")},
        {"budget_kind": "cost", "limit": -1.0},
        {"budget_kind": "cost", "limit": 0},
        {"budget_kind": "cost", "limit": True},
        {"budget_kind": "cost", "limit": "250"},
        {"budget_kind": "megabytes", "limit": 250.0},
        {"budget_kind": "cost"},
        {},
    ]
    poller = ScriptedPoller(
        [(_budget(250.0),)]
        + [
            (_command("set_budget", command_id=f"cmd-bad-{index}", parameters=parameters),)
            for index, parameters in enumerate(invalid)
        ]
    )
    try:
        loop = _loop(observer, control=poller, synthetic_cost_per_turn=100.0)
        terminals = _drive(loop, 3, calls)
    finally:
        observer.close(timeout=1)
    # A NaN limit is the one that matters most: every comparison against it is
    # false, so an accepted NaN is a budget that silently never triggers.
    assert loop.budget_limit == 250.0
    assert [terminal["status"] for terminal in terminals] == [
        "completed",
        "completed",
        "budget_exceeded",
    ]
    errors = [event for event in sink.events if event["type"] == "error"]
    assert errors and errors[0]["data"]["code"] == "REFERENCE_BUDGET_PARAMETERS_INVALID"
    assert len(calls) == 2

    # Every invalid shape is refused, not just the first.
    sink = Sink()
    observer = BoundedObserver(sink)
    try:
        loop = _loop(
            observer,
            control=ScriptedPoller(
                [
                    (_command("set_budget", command_id=f"cmd-bad-{index}", parameters=parameters),)
                    for index, parameters in enumerate(invalid)
                ]
            ),
        )
        _drive(loop, len(invalid), [])
        assert loop.budget_limit is None
    finally:
        observer.close(timeout=1)


def test_a_redelivered_budget_does_not_re_announce_itself():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    budget = _budget(1000.0)
    poller = ScriptedPoller([(budget,), (budget,), (budget,)])
    try:
        _drive(_loop(observer, control=poller, synthetic_cost_per_turn=1.0), 3, calls)
    finally:
        observer.close(timeout=1)
    assert [
        event["data"]["action"] for event in sink.events if event["type"] == "control"
    ] == ["set_budget"]


def test_a_pause_takes_precedence_over_a_breached_budget():
    # Both halt the turn, so the only observable difference is which reason the
    # trace records. Pause is the operator's most recent explicit instruction
    # about whether to act at all; the budget is a standing ceiling.
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_budget(50.0), _command("pause", command_id="cmd-pause-1"))])
    try:
        terminals = _drive(_loop(observer, control=poller, synthetic_cost_per_turn=100.0), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0]["status"] == "paused"
    assert calls == []


def test_a_budget_delivered_to_a_paused_agent_is_not_lost():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller(
        [
            (_command("pause", command_id="cmd-pause-1"),),
            (_budget(50.0),),
            (_command("resume", command_id="cmd-resume-1"),),
        ]
    )
    try:
        loop = _loop(observer, control=poller, synthetic_cost_per_turn=100.0)
        terminals = _drive(loop, 3, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == [
        "paused",
        "paused",
        "budget_exceeded",
    ]
    # The resume released the pause and the ceiling then bit on the same turn:
    # the budget arrived while paused and was not dropped.
    assert loop.budget_limit == 50.0
    assert calls == []


def test_a_stop_wins_over_a_budget_delivered_in_the_same_batch():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    poller = ScriptedPoller([(_budget(50.0), _stop_command(command_id="cmd-stop-1"))])
    try:
        terminals = _drive(_loop(observer, control=poller, synthetic_cost_per_turn=100.0), 1, calls)
    finally:
        observer.close(timeout=1)
    assert terminals[0] == {"status": "stopped", "control_command_id": "cmd-stop-1"}


def test_a_budget_is_never_breached_by_a_run_with_no_ceiling():
    sink = Sink()
    observer = BoundedObserver(sink)
    calls = []
    try:
        loop = _loop(observer, control=ScriptedPoller([]), synthetic_cost_per_turn=1e12)
        terminals = _drive(loop, 3, calls)
    finally:
        observer.close(timeout=1)
    assert [terminal["status"] for terminal in terminals] == ["completed"] * 3
    assert loop.budget_limit is None
    assert len(calls) == 3
