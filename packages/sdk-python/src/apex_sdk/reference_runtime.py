"""Small deterministic reason-act loop used to exercise the Phase 0 contract."""

from __future__ import annotations

import secrets
import hashlib
import math
import re
import time
from datetime import UTC, datetime
from typing import Any, Callable
from uuid import UUID

from .control import ControlAction, ControlCommand, ControlValidationError
from .event import EventBuilder
from .observer import BoundedObserver
from .validation import MAX_CONTROL_BUDGET_LIMIT

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

#: How many already-enacted ``command_id`` values the loop remembers.
#:
#: This is **not** a second acknowledgement protocol. The gateway's inbox
#: (``apps/control-plane-api/src/inbox.rs``) owns delivery state and is
#: deliberately at-least-once: a delivered command is suppressed for a
#: redelivery window and then becomes visible again, up to a bounded number of
#: attempts. That is the right durability trade, and it means a cooperating
#: runtime sees the same ``command_id`` more than once. This set is only what
#: makes *enactment* idempotent on the receiving side, so a redelivered
#: ``pause`` does not re-announce itself and a redelivered ``resume`` cannot
#: un-pause a pause issued after it.
#:
#: Bounded because it is a process-lifetime structure fed by a remote party.
#: The gateway stops redelivering a command after
#: ``DEFAULT_MAX_DELIVERY_ATTEMPTS`` (8) attempts over roughly four minutes, so
#: remembering the last few hundred is far more than the window needs.
MAX_REMEMBERED_COMMANDS = 512


def _non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ControlValidationError(f"{name} must be a non-negative integer")
    return value


def _non_negative_number(value: Any, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ControlValidationError(f"{name} must be a non-negative finite number")
    return float(value)


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

    Optionally cooperative: given a ``control`` poller, the loop checks for
    pending commands at one honest checkpoint -- immediately before it would
    execute the tool -- and enacts them.

    This is a small synthetic single-turn loop for exercising the event
    contract, not a production runtime, so there is deliberately no general
    "checkpoint" abstraction here. One real check in the one place a real
    runtime would obviously put one is what proves the mechanism; generalising
    it into a control-integration API is a separate piece of work.

    State that outlives one ``run()``
    ---------------------------------
    ``run()`` is one *turn*, and a caller drives many turns on one instance
    (``deploy/compose/gateway-ref/agent_under_control.py`` is exactly that
    shape). Three things therefore live on the instance rather than in a turn:

    - **Paused-ness.** A ``pause`` is not a property of the turn that received
      it; it holds until a ``resume`` arrives.
    - **Running-total usage and the ceiling in force**, so ``set_budget`` is a
      ceiling on the *run* rather than on a single turn, which is what makes
      it a budget at all.
    - **Which commands have already been enacted**, so at-least-once
      redelivery does not re-enact anything (see
      :data:`MAX_REMEMBERED_COMMANDS`).

    Enactment order at the checkpoint, and why it is this order
    -----------------------------------------------------------
    1. ``stop`` -- unconditional and immediate. It wins over everything,
       including a ``pause`` delivered in the same batch; nothing else in the
       batch is applied, because there is no later turn for any of it to
       affect.
    2. ``set_budget`` -- a state update, never a halt of its own. Applied
       before the budget check so a ceiling arriving on this poll governs this
       turn, and before the pause halt so a ceiling delivered to a paused
       agent is not lost.
    3. ``pause``/``resume`` -- if the result is "paused", the turn ends here
       without executing the tool.
    4. The budget check -- if accumulated usage has passed the ceiling, the
       turn ends here without executing the tool.

    ``inject`` is retrieved and deliberately left inert until its own pass
    lands. An agent that silently ignores it is honest; one that pretends to
    have consumed it is not.

    Within one poll, ``pause`` and ``resume`` are folded in delivery order.
    The gateway returns commands oldest-first (``inbox.rs`` preserves
    insertion order), so "the operator's last instruction wins" is
    well-defined rather than a race. **Flagged for the owner:** the
    alternative rule -- a ``pause`` anywhere in a batch always wins -- is
    marginally more conservative but ignores an explicit later ``resume``,
    which is its own failure mode.
    """

    def __init__(
        self,
        observer: BoundedObserver,
        *,
        agent_id: str,
        scope: dict[str, Any],
        version: dict[str, str],
        control: Any | None = None,
        synthetic_input_tokens: int = 0,
        synthetic_output_tokens: int = 0,
        synthetic_cost_per_turn: float = 0.0,
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
        # The synthetic per-turn usage this loop reports on its `llm` event.
        # Zero by default, which is what every existing caller gets. A
        # non-zero value exists so `set_budget` enforcement can be *proven*:
        # with `input_tokens: 0, output_tokens: 0` a budget can never be
        # exceeded, so "the agent halted on its budget" would be unfalsifiable.
        self._synthetic_input_tokens = _non_negative_int(
            synthetic_input_tokens, "synthetic_input_tokens"
        )
        self._synthetic_output_tokens = _non_negative_int(
            synthetic_output_tokens, "synthetic_output_tokens"
        )
        self._synthetic_cost_per_turn = _non_negative_number(
            synthetic_cost_per_turn, "synthetic_cost_per_turn"
        )
        self._paused_by: str | None = None
        self._budget_kind: str | None = None
        self._budget_limit: float | None = None
        self._budget_command_id: str | None = None
        self._used_tokens = 0
        self._used_cost = 0.0
        # Insertion-ordered set. `dict` rather than `set` because eviction has
        # to be oldest-first to be bounded in a useful way.
        self._enacted: dict[str, None] = {}

    # -- observable state, for a harness driving many turns -----------------

    @property
    def paused_by(self) -> str | None:
        """The ``command_id`` of the ``pause`` in force, or ``None``."""
        return self._paused_by

    @property
    def budget_kind(self) -> str | None:
        """``"tokens"`` or ``"cost"``, or ``None`` when no ceiling is set."""
        return self._budget_kind

    @property
    def budget_limit(self) -> float | None:
        return self._budget_limit

    @property
    def budget_command_id(self) -> str | None:
        """The ``command_id`` of the ``set_budget`` currently in force."""
        return self._budget_command_id

    @property
    def used_tokens(self) -> int:
        return self._used_tokens

    @property
    def used_cost(self) -> float:
        return self._used_cost

    def _first_sight(self, command_id: str) -> bool:
        """True the first time this ``command_id`` is seen; False afterwards.

        Records as a side effect, so a caller cannot decide to enact something
        twice by forgetting to mark it.
        """
        if command_id in self._enacted:
            return False
        self._enacted[command_id] = None
        while len(self._enacted) > MAX_REMEMBERED_COMMANDS:
            self._enacted.pop(next(iter(self._enacted)))
        return True

    def _poll(self, emit: Callable[[str, dict[str, Any]], None]) -> tuple[Any, ...]:
        """Polls the control channel and returns the commands it delivered.

        Retrieval *is* the acknowledgement: the gateway durably records the
        delivery attempt before it returns a command, so a command this call
        observes is marked delivered on the gateway side. Delivery is
        at-least-once, so the same command may be seen again after the
        gateway's redelivery window -- which is safe because enactment here is
        idempotent per ``command_id`` (see :meth:`_first_sight`), and because
        for ``stop`` it is trivially so: a run that has already ended cannot
        end twice.

        **A poll failure does not stop the run**, and that is a decision worth
        stating rather than leaving implicit. The alternative -- halt whenever
        the control channel is unreachable -- would turn a blip on the
        out-of-band channel into a fleet-wide outage, and the whole reason
        ADR-0006 keeps this channel independent is that the rest of the
        platform being degraded must not take agents down. The failure is
        emitted as an `error` event so the trace shows the check did not
        happen, rather than showing nothing and implying it passed.

        Note what a poll failure does **not** do: it does not clear paused-ness
        or a budget ceiling. Those are state the agent already holds, and an
        unreachable gateway is not a reason to start running again.

        **Flagged for the owner:** if a deployment would rather fail closed --
        an agent that cannot confirm it is un-stopped must stop -- that is a
        policy switch, not a bug fix, and it belongs in the control-integration
        API that is out of scope for this pass.
        """
        if self._control is None:
            return ()
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
            return ()
        return tuple(getattr(result, "commands", ()))

    @staticmethod
    def _reason_code(command: Any) -> str | None:
        """The command's ``reason_code``, or ``None`` if it is not safe to echo.

        Operator-supplied text. It must never be able to make a command
        un-enactable by failing event validation on the way out.
        """
        reason_code = getattr(command, "reason_code", None)
        if reason_code is None:
            return None
        return reason_code if _SAFE_IDENTIFIER.fullmatch(str(reason_code)) else None

    def _enact(
        self, emit: Callable[[str, dict[str, Any]], None]
    ) -> tuple[dict[str, Any] | None, dict[str, Any], str | None]:
        """Polls, applies every pending command, and reports the consequence.

        Returns ``(terminal, extra, resumed_by)``. A non-``None`` ``terminal``
        is the ``turn_end`` data for a turn that must **not** execute its
        tool. ``extra`` is merged into whichever terminal event the turn ends
        up emitting, so a fact about this turn (which command resumed it,
        which content was injected into it) survives regardless of how the
        turn ends. ``resumed_by`` is set when this turn is the one that came
        out of a pause.

        See the class docstring for why the order below is the order.
        """
        stop: Any | None = None
        pause_intent: Any | None = None
        budgets: list[Any] = []
        for command in self._poll(emit):
            action = getattr(command, "action", None)
            if action == "stop":
                # Deliberately not subject to `_first_sight`: a redelivered
                # `stop` must still halt a loop that somehow kept running, and
                # there is no state to corrupt by enacting it twice.
                if stop is None:
                    stop = command
                continue
            command_id = str(getattr(command, "command_id", ""))
            if not command_id or not self._first_sight(command_id):
                # A redelivery of something already enacted. Ignoring it is
                # what makes at-least-once delivery safe here -- in
                # particular, a `resume` redelivered after a *later* `pause`
                # must not un-pause the agent.
                continue
            if action in ("pause", "resume"):
                pause_intent = command
            elif action == "set_budget":
                budgets.append(command)
            # `inject` is retrieved and deliberately left inert until its own
            # pass lands, rather than half-implemented: an agent that silently
            # ignores it is honest, an agent that pretends to have consumed it
            # is not. Any other action -- including one this SDK decodes as
            # "unspecified" because the gateway is newer than the client -- is
            # inert for the same reason.

        if stop is not None:
            emit(
                "control",
                ControlCommand.create(
                    ControlAction.STOP, reason_code=self._reason_code(stop)
                ).to_event_data(),
            )
            return (
                {
                    "status": "stopped",
                    # Ties this run's ending to the operator's command in the
                    # same queryable trace, which is the only way to answer
                    # "did my stop actually do anything".
                    "control_command_id": str(getattr(stop, "command_id", "")),
                },
                {},
                None,
            )

        extra: dict[str, Any] = {}
        for command in budgets:
            self._apply_budget(command, emit)
        resumed_by = self._apply_pause_intent(pause_intent, emit)
        if self._paused_by is not None:
            # Every turn a paused agent starts still has to *end*, or the
            # trace shows a turn that began and never finished -- the same
            # "looks like a crash" ambiguity a silent return would produce.
            # So the terminal event repeats every turn while the `control`
            # event announcing the pause is emitted exactly once, on the
            # transition. That is the documented answer to "does a paused
            # agent re-announce itself forever": no, but it does keep saying
            # honestly that it did nothing.
            return (
                {"status": "paused", "control_command_id": self._paused_by, **extra},
                {},
                None,
            )
        exceeded = self._budget_exceeded()
        if exceeded is not None:
            # The budget is why this turn ended, so it owns the terminal
            # event's `control_command_id` even on a turn that also resumed.
            return ({"status": "budget_exceeded", **extra, "control_command_id": exceeded}, {}, None)
        if resumed_by is not None:
            extra["control_command_id"] = resumed_by
        return (None, extra, resumed_by)

    def _apply_pause_intent(
        self, command: Any | None, emit: Callable[[str, dict[str, Any]], None]
    ) -> str | None:
        """Applies a ``pause`` or ``resume``. Returns a resuming ``command_id``.

        Both directions are safe no-ops when the agent is already in the state
        being asked for: a second ``pause`` while paused changes nothing, and
        a ``resume`` for an agent that was never paused changes nothing. Being
        no-ops rather than errors is the point -- an operator who is not sure
        whether an agent is paused must be able to send ``resume`` without
        risking an error path.
        """
        if command is None:
            return None
        command_id = str(getattr(command, "command_id", ""))
        if getattr(command, "action", None) == "pause":
            if self._paused_by is not None:
                return None
            self._paused_by = command_id
            emit(
                "control",
                ControlCommand.create(
                    ControlAction.PAUSE, reason_code=self._reason_code(command)
                ).to_event_data(),
            )
            return None
        if self._paused_by is None:
            return None
        self._paused_by = None
        emit(
            "control",
            # No `reason_code`: `ControlCommand` refuses one on `resume`, and
            # the operator's own `control` event in the trace (actor type
            # `user`) retains whatever they submitted. Passing it through here
            # would raise inside the enactment path, which is the one place a
            # rejected field must never be able to reach.
            ControlCommand.create(ControlAction.RESUME).to_event_data(),
        )
        return command_id

    def _apply_budget(
        self, command: Any, emit: Callable[[str, dict[str, Any]], None]
    ) -> None:
        """Installs a ``set_budget`` ceiling. Never halts a turn by itself.

        The parameters are **re-validated here** rather than trusted because
        they were validated at the gateway. Two different reasons, both real:
        the gateway and this SDK could disagree after a version skew, and a
        value that reached an enforcement comparison as ``NaN`` would make
        every comparison false -- a budget that silently never triggers, which
        is worse than no budget because it looks like one.

        An invalid ceiling is **refused, not approximated**: the previous
        ceiling stays in force and an `error` event records that this command
        did nothing. Guessing at what an operator meant is not available to a
        cost control.
        """
        parameters = getattr(command, "parameters", None) or {}
        kind = parameters.get("budget_kind") if isinstance(parameters, dict) else None
        limit = parameters.get("limit") if isinstance(parameters, dict) else None
        if (
            kind not in ("tokens", "cost")
            or isinstance(limit, bool)
            or not isinstance(limit, (int, float))
            or not math.isfinite(limit)
            or limit <= 0
            or limit > MAX_CONTROL_BUDGET_LIMIT
        ):
            emit(
                "error",
                {
                    "code": "REFERENCE_BUDGET_PARAMETERS_INVALID",
                    "summary": "A budget command was retrieved but could not be enforced.",
                    "cause": "The command's budget_kind or limit did not satisfy the control contract.",
                    "retryable": False,
                    "recommended_next_steps": [
                        "Resubmit the budget with budget_kind of tokens or cost and a positive finite limit.",
                        "Treat this agent as running under its previous ceiling, not the requested one.",
                    ],
                },
            )
            return
        self._budget_kind = kind
        self._budget_limit = float(limit)
        self._budget_command_id = str(getattr(command, "command_id", ""))
        emit(
            "control",
            ControlCommand.create(
                ControlAction.SET_BUDGET,
                reason_code=self._reason_code(command),
                budget_kind=kind,
                limit=limit,
            ).to_event_data(),
        )

    def _budget_exceeded(self) -> str | None:
        """The ``command_id`` of the ceiling this turn would breach, if any.

        The comparison is against the running total *including this turn*,
        because the turn's `llm` event has already been emitted and counted by
        the time the checkpoint runs. That is the same thing as "accumulated
        usage plus this turn's projected cost", and it is why the halt lands
        on the first turn whose completion would put the run over rather than
        on the turn after it.

        **Usage accumulated before the ceiling arrived counts against it.** A
        `set_budget` is a statement about the run, so an operator capping an
        already-expensive agent halts it at once rather than granting it a
        fresh allowance. That is the conservative reading and the one a cost
        control is for; *flagged for the owner* as a choice, since "from here
        on" is a defensible alternative.
        """
        if self._budget_limit is None:
            return None
        used = self._used_tokens if self._budget_kind == "tokens" else self._used_cost
        if used <= self._budget_limit:
            return None
        return self._budget_command_id or ""

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
        input_tokens = self._synthetic_input_tokens
        output_tokens = self._synthetic_output_tokens
        # The running total is advanced where the `llm` event is emitted,
        # because that event *is* this loop's record of the model call. A turn
        # that is about to halt at the checkpoint below has still made its
        # model call, and pretending otherwise would make the usage total
        # disagree with the trace it is derived from.
        self._used_tokens += input_tokens + output_tokens
        self._used_cost += self._synthetic_cost_per_turn
        emit(
            "llm",
            {
                "provider": "reference",
                "model": model_name,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "execution": build_execution(
                    requested_provider="reference",
                    requested_model=model_name,
                    effective_provider="reference",
                    effective_model=model_name,
                    routing_reason="configured",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
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
        terminal_extra: dict[str, Any] = {}
        resumed_by: str | None = None
        if tool is not None:
            # The checkpoint. Before the side effect, not after it: a `stop`
            # observed after the tool has already run has not stopped
            # anything, and a `pause` that lets one more tool call through is
            # not a pause.
            terminal, terminal_extra, resumed_by = self._enact(emit)
            if terminal is not None:
                # A terminal event, not a silent return. An operator reading
                # the trace has to be able to see *why* the turn ended -- a run
                # that just stops emitting is indistinguishable from a crash,
                # which is the same "looks fine, means nothing" failure this
                # whole work item exists to remove.
                emit("turn_end", terminal)
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
                emit("turn_end", {"status": "error", **terminal_extra})
                return events
        # `resumed` rather than `completed` names the one turn that came out of
        # a pause, and carries the `resume` command's id, so an operator can
        # answer "did my resume actually restart it" from the trace alone --
        # the same question `stopped`/`control_command_id` answers for a stop.
        # The turn genuinely completed: the `tool` and `message` events above
        # are in the trace ahead of this one.
        emit(
            "turn_end",
            {"status": "resumed" if resumed_by is not None else "completed", **terminal_extra},
        )
        return events
