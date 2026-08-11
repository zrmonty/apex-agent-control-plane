"""Small deterministic reason-act loop used to exercise the Phase 0 contract."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Callable

from .event import EventBuilder
from .observer import BoundedObserver
from ._reference_control import MAX_REMEMBERED_COMMANDS, _ControlEnactment
from ._reference_helpers import _SAFE_IDENTIFIER, _non_negative_int, _non_negative_number, _uuid7


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
    3. ``inject`` -- surfaced into the trace as untrusted content. Never
       halts, never parsed. Applied before the halting checks so an
       operator's content is recorded even on a turn that will not act on
       it, then acknowledged after the runtime has processed it.
    4. ``resolve_hold`` -- applied against the hold this loop is actually
       waiting on, if any (see :meth:`enter_hold`). Unblocks either way: an
       ``approved`` decision lets the turn continue to the remaining checks
       below (and on to the tool, if nothing else halts it); a ``denied``
       decision ends the turn without running the tool, the same as
       ``stop``/``pause`` do, but only for this one held call rather than the
       whole run.
    5. ``pause``/``resume`` -- if the result is "paused", the turn ends here
       without executing the tool.
    6. The budget check -- if accumulated usage has passed the ceiling, the
       turn ends here without executing the tool.
    7. The hold check -- if this loop is still waiting on a hold (nothing in
       this poll resolved it), the turn ends here without executing the
       tool, repeating every turn exactly as a standing ``pause`` does.

    Within one poll, ``pause`` and ``resume`` are folded in delivery order.
    The gateway returns commands oldest-first (``inbox.rs`` preserves
    insertion order), so "the operator's last instruction wins" is
    well-defined rather than a race. **Flagged for the owner:** the
    alternative rule -- a ``pause`` anywhere in a batch always wins -- is
    marginally more conservative but ignores an explicit later ``resume``,
    which is its own failure mode.

    Implementation note: the control-channel mechanics described above --
    polling, dispatch, and every piece of state the enactment order reads or
    writes -- live on a private ``_ControlEnactment`` delegate this class
    owns (``_reference_control.py``), not on this class directly. This class
    is left owning only the turn-loop mechanics: building and emitting the
    reason-act trace itself. See that module's docstring for why.
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
        self._control_enactment = _ControlEnactment(control)

    # -- observable state, for a harness driving many turns -----------------
    # Forwarded to the `_ControlEnactment` delegate that actually owns this
    # state -- see that class for the state itself and its invariants.

    @property
    def paused_by(self) -> str | None:
        """The ``command_id`` of the ``pause`` in force, or ``None``."""
        return self._control_enactment.paused_by

    @property
    def held_token(self) -> str | None:
        """The ``hold_token`` this loop is currently waiting on, or ``None``."""
        return self._control_enactment.held_token

    def enter_hold(self) -> str:
        """Suspends the next tool call pending an operator decision.

        See ``_ControlEnactment.enter_hold`` for the full explanation; this
        forwards to it unchanged.
        """
        return self._control_enactment.enter_hold()

    @property
    def budget_kind(self) -> str | None:
        """``"tokens"`` or ``"cost"``, or ``None`` when no ceiling is set."""
        return self._control_enactment.budget_kind

    @property
    def budget_limit(self) -> float | None:
        return self._control_enactment.budget_limit

    @property
    def budget_command_id(self) -> str | None:
        """The ``command_id`` of the ``set_budget`` currently in force."""
        return self._control_enactment.budget_command_id

    @property
    def used_tokens(self) -> int:
        return self._control_enactment.used_tokens

    @property
    def used_cost(self) -> float:
        return self._control_enactment.used_cost

    # -- back-compat shims -----------------------------------------------
    # `_ControlEnactment` is where `_control`, `_enacted`, and `_first_sight`
    # actually live now. These forward to it so that reaching into this
    # loop's control-enactment internals directly -- as some tests
    # deliberately do, e.g. to script a mid-run poller swap or to probe the
    # dedup-eviction boundary -- keeps working exactly as it did before the
    # split.

    @property
    def _control(self) -> Any:
        return self._control_enactment._control

    @_control.setter
    def _control(self, value: Any) -> None:
        self._control_enactment._control = value

    @property
    def _enacted(self) -> dict[str, None]:
        return self._control_enactment._enacted

    def _first_sight(self, command_id: str) -> bool:
        return self._control_enactment._first_sight(command_id)

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
        self._control_enactment.record_usage(input_tokens + output_tokens, self._synthetic_cost_per_turn)
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
            terminal, terminal_extra, resumed_by = self._control_enactment._enact(emit)
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
