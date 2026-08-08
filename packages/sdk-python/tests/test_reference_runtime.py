import hashlib

from apex_sdk import (
    BoundedObserver,
    InMemoryControlPoller,
    PendingControlCommand,
    ReferenceReasonActLoop,
)


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


def _loop(observer, control=None):
    return ReferenceReasonActLoop(
        observer,
        agent_id="agent",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        control=control,
    )


def _stop_command(reason_code="operator.request", command_id="018f0000-0000-7000-8000-000000000001"):
    return PendingControlCommand(
        command_id=command_id,
        workspace_id="acme",
        namespace_id="prod",
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        action="stop",
        reason_code=reason_code,
        issued_at="2026-08-08T00:00:00.000000Z",
        delivery_attempt=1,
    )


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
    # `pause` is retrieved and deliberately not acted on. An agent that
    # silently ignores it is honest; one that pretends to pause is not.
    sink = Sink()
    observer = BoundedObserver(sink)
    paused = PendingControlCommand(
        command_id="cmd-pause",
        workspace_id="acme",
        namespace_id="prod",
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        action="pause",
        reason_code=None,
        issued_at="2026-08-08T00:00:00.000000Z",
        delivery_attempt=1,
    )
    try:
        events = _loop(observer, control=InMemoryControlPoller([paused])).run(
            "prompt-ref", tool=lambda value: "result"
        )
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
