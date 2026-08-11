"""Tests for ``ReferenceReasonActLoop``'s cooperative ``set_budget`` enactment.

Split out of a larger ``test_reference_runtime.py`` -- see that file for
basic turn-loop mechanics, and ``test_reference_runtime_stop.py`` /
``_pause.py`` / ``_inject.py`` / ``_hold.py`` for the other cooperative
control actions.
"""

from apex_sdk import BoundedObserver
from conftest import Sink, _budget, _command, _drive, _loop, ScriptedPoller, _stop_command


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
