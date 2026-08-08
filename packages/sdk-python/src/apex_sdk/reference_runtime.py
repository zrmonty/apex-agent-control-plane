"""Small deterministic reason-act loop used to exercise the Phase 0 contract."""

from __future__ import annotations

import secrets
import hashlib
import re
import time
from datetime import UTC, datetime
from typing import Any, Callable
from uuid import UUID

from .control import ControlAction, ControlCommand
from .event import EventBuilder
from .observer import BoundedObserver

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


def _uuid7() -> str:
    milliseconds = int(time.time() * 1000)
    value = (milliseconds << 80) | (secrets.randbits(76) & ((1 << 76) - 1))
    value &= ~(0xF << 76)
    value |= 0x7 << 76
    value &= ~(0x3 << 62)
    value |= 0x2 << 62
    return str(UUID(int=value))


class ReferenceReasonActLoop:
    """Emit a readable start/LLM/tool/message/end trace through an observer.

    Optionally cooperative: given a ``control`` poller, the loop checks for a
    pending ``stop`` at one honest checkpoint -- immediately before it would
    execute the tool -- and ends the run instead of executing it.

    This is a small synthetic single-turn loop for exercising the event
    contract, not a production runtime, so there is deliberately no general
    "checkpoint" abstraction here. One real check in the one place a real
    runtime would obviously put one is what proves the mechanism; generalising
    it into a control-integration API is a separate piece of work.
    """

    def __init__(
        self,
        observer: BoundedObserver,
        *,
        agent_id: str,
        scope: dict[str, Any],
        version: dict[str, str],
        control: Any | None = None,
    ) -> None:
        self._observer = observer
        self._agent_id = agent_id
        self._scope = scope
        self._version = version
        # Any object with a `poll(*, max_commands=...)` returning something
        # with a `.commands` sequence: the real `GrpcControlTransport`, an
        # `InMemoryControlPoller`, or a future subscription-based client. The
        # loop does not import the transport, so the SDK still works with no
        # gRPC stack installed.
        self._control = control

    def _pending_stop(self, emit: Callable[[str, dict[str, Any]], None]) -> Any | None:
        """Polls the control channel and returns a pending ``stop``, if any.

        Retrieval *is* the acknowledgement: the gateway durably records the
        delivery attempt before it returns a command, so a command this call
        observes is marked delivered on the gateway side. Delivery is
        at-least-once, so the same ``stop`` may be seen again after the
        gateway's redelivery window -- which is safe precisely because acting
        on it is idempotent: a run that has already ended cannot end twice.

        **A poll failure does not stop the run**, and that is a decision worth
        stating rather than leaving implicit. The alternative -- halt whenever
        the control channel is unreachable -- would turn a blip on the
        out-of-band channel into a fleet-wide outage, and the whole reason
        ADR-0006 keeps this channel independent is that the rest of the
        platform being degraded must not take agents down. The failure is
        emitted as an `error` event so the trace shows the check did not
        happen, rather than showing nothing and implying it passed.

        **Flagged for the owner:** if a deployment would rather fail closed --
        an agent that cannot confirm it is un-stopped must stop -- that is a
        policy switch, not a bug fix, and it belongs in the control-integration
        API that is out of scope for this pass.
        """
        if self._control is None:
            return None
        try:
            result = self._control.poll()
        except Exception:
            emit(
                "error",
                {
                    "code": "CONTROL_POLL_UNAVAILABLE",
                    "summary": "Pending control commands could not be retrieved before the tool step.",
                    "cause": "The control channel poll failed, so this run could not confirm whether a stop is pending.",
                    "retryable": True,
                    "recommended_next_steps": [
                        "Check control gateway reachability and the agent workload credential.",
                        "Treat this run as un-checked rather than confirmed un-stopped.",
                    ],
                },
            )
            return None
        for command in getattr(result, "commands", ()):
            # Only `stop` is enacted in this pass. Other actions are retrieved
            # and deliberately left inert rather than half-implemented: an
            # agent that silently ignores `pause` is honest, an agent that
            # pretends to pause is not.
            if getattr(command, "action", None) == "stop":
                return command
        return None

    def run(
        self,
        prompt: str,
        *,
        tool: Callable[[str], str] | None = None,
        child_agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        run_id, trace_id = _uuid7(), _uuid7()
        builder = EventBuilder(
            agent_id=self._agent_id,
            run_id=run_id,
            trace_id=trace_id,
            scope=self._scope,
            actor={"type": "agent", "id": self._agent_id},
            version=self._version,
        )
        events: list[dict[str, Any]] = []

        def emit_from(active_builder: EventBuilder, event_type: str, data: dict[str, Any]) -> None:
            event = active_builder.build(event_type, data, event_id=_uuid7(), timestamp=datetime.now(UTC))
            if self._observer.emit(event):
                events.append(event)

        def emit(event_type: str, data: dict[str, Any]) -> None:
            emit_from(builder, event_type, data)

        from .execution import build_execution

        prompt_ref = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        emit("turn_start", {"prompt_ref": prompt_ref})
        model_name = self._version["model"]
        emit(
            "llm",
            {
                "provider": "reference",
                "model": model_name,
                "input_tokens": 0,
                "output_tokens": 0,
                "execution": build_execution(
                    requested_provider="reference",
                    requested_model=model_name,
                    effective_provider="reference",
                    effective_model=model_name,
                    routing_reason="configured",
                    input_tokens=0,
                    output_tokens=0,
                    evidence_source="sdk_observed",
                ),
            },
        )
        if child_agent_id is not None:
            if _SAFE_IDENTIFIER.fullmatch(child_agent_id) is None:
                emit(
                    "error",
                    {
                        "code": "REFERENCE_CHILD_ID_INVALID",
                        "summary": "The child agent could not be spawned.",
                        "cause": "The child agent identifier is missing or violates the safe identifier contract.",
                        "retryable": False,
                        "recommended_next_steps": ["Use a 1–256 character ASCII child agent identifier."],
                    },
                )
                emit("turn_end", {"status": "error"})
                return events
            child_run_id = _uuid7()
            emit("agent_spawn", {"child_agent_id": child_agent_id, "child_run_id": child_run_id})
            child_builder = EventBuilder(
                agent_id=child_agent_id,
                run_id=child_run_id,
                trace_id=trace_id,
                parent_run_id=run_id,
                scope=self._scope,
                actor={"type": "agent", "id": child_agent_id},
                version=self._version,
            )
            emit_from(child_builder, "turn_start", {"prompt_ref": prompt_ref})
            emit_from(child_builder, "turn_end", {"status": "completed"})
        if tool is not None:
            # The checkpoint. Before the side effect, not after it: a `stop`
            # observed after the tool has already run has not stopped
            # anything.
            stop = self._pending_stop(emit)
            if stop is not None:
                # A terminal event, not a silent return. An operator reading
                # the trace has to be able to see *why* the run ended -- a run
                # that just stops emitting is indistinguishable from a crash,
                # which is the same "looks fine, means nothing" failure this
                # whole work item exists to remove.
                reason_code = getattr(stop, "reason_code", None)
                emit(
                    "control",
                    ControlCommand.create(
                        ControlAction.STOP,
                        reason_code=reason_code if _SAFE_IDENTIFIER.fullmatch(str(reason_code or "")) else None,
                    ).to_event_data(),
                )
                emit(
                    "turn_end",
                    {
                        "status": "stopped",
                        # Ties this run's ending to the operator's command in
                        # the same queryable trace, which is the only way to
                        # answer "did my stop actually do anything".
                        "control_command_id": str(getattr(stop, "command_id", "")),
                    },
                )
                return events
            tool_input = "reference-input"
            emit("tool", {"name": "reference_tool", "input_ref": tool_input})
            try:
                tool_result = tool(tool_input)
                if not isinstance(tool_result, str):
                    raise TypeError("tool result must be text")
                emit(
                    "message",
                    {
                        "role": "tool",
                        "content_ref": hashlib.sha256(tool_result.encode("utf-8")).hexdigest(),
                    },
                )
            except Exception:
                emit(
                    "error",
                    {
                        "code": "REFERENCE_TOOL_FAILED",
                        "summary": "The reference tool step failed.",
                        "cause": "The configured tool callback raised an exception or returned an unsupported result type.",
                        "retryable": False,
                        "recommended_next_steps": [
                            "Inspect the tool implementation and its bounded input contract.",
                            "Retry the run after the tool reports a valid text result.",
                        ],
                    },
                )
                emit("turn_end", {"status": "error"})
                return events
        emit("turn_end", {"status": "completed"})
        return events
