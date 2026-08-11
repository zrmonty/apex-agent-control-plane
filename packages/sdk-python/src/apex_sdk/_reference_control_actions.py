"""Individual control-command action handlers for :class:`_ControlEnactment`.

Split out of ``_reference_control.py``: ``pause``/``resume``, ``set_budget``,
``inject``, and the budget-breach check were originally methods on the same
class that owns the enactment state and the poll/dispatch orchestration
(``_ControlEnactment._enact``). Splitting one class's methods across files
isn't something Python supports directly, so these are plain functions
instead, each taking the owning ``_ControlEnactment`` as an explicit first
argument (named ``enactment``) in place of an implicit ``self``. That is a
mechanical rewrite -- ``self.x`` becomes ``enactment.x`` throughout, which is
exactly what a bound-method call already desugars to -- not a behavior
change, and it is what keeps ``_reference_control.py`` itself short enough to
read as "poll, dispatch, and the state those actions share" without also
carrying every action's own logic.

``_surface_inject`` and ``_budget_exceeded`` are the two exceptions: the
former never touched enactment state even as a method (only ``command`` and
``emit``), and the latter only reads state, so it takes ``enactment`` without
needing to mutate it. Both are kept here anyway, next to the other action
handlers, because grouping by "one action, one function" is easier to follow
than grouping by "does this one happen to mutate its argument".
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Callable

from .control import ControlAction, ControlCommand
from .validation import MAX_CONTROL_BUDGET_LIMIT, MAX_UNTRUSTED_CONTROL_CONTENT_BYTES
from ._reference_helpers import _reason_code

if TYPE_CHECKING:
    from ._reference_control import _ControlEnactment


def _apply_resolve_hold(
    enactment: "_ControlEnactment", commands: Sequence[Any], emit: Callable[[str, dict[str, Any]], None]
) -> tuple[str, str, str | None] | None:
    """Applies the ``resolve_hold`` that matches the hold this loop is
    actually waiting on, if any. Returns ``(decision, command_id, reason)``
    for the match, or ``None`` otherwise.

    Every other ``resolve_hold`` in the batch is a **safe no-op**, the
    same idempotence discipline ``stop`` already has for an
    already-stopped loop:

    - **Not currently held** (``enactment._held_token`` is ``None``) -- there
      is nothing to resolve, so every command here is inert.
    - **Wrong identifier** -- a ``hold_token`` that does not match
      ``enactment._held_token`` is not this hold, whether it names a stale
      hold from earlier in the run or one this loop was never told
      about.
    - **Already resolved / a redelivered duplicate** -- resolving clears
      ``enactment._held_token`` immediately, so a second delivery of the same
      command (or of a *different* command still naming the
      now-cleared token) can no longer match anything. Combined with
      ``_first_sight``'s ``command_id`` dedup on the same command, a
      redelivery is caught twice over.

    Only the first match in delivery order is applied -- one hold can be
    in force at a time, so there is at most one to find.
    """
    for command in commands:
        if enactment._held_token is None:
            break
        parameters = getattr(command, "parameters", None)
        hold_token = parameters.get("hold_token") if isinstance(parameters, dict) else None
        if not isinstance(hold_token, str) or hold_token != enactment._held_token:
            continue
        decision = parameters.get("decision") if isinstance(parameters, dict) else None
        if decision not in ("approved", "denied"):
            emit(
                "error",
                {
                    "code": "REFERENCE_RESOLVE_HOLD_PARAMETERS_INVALID",
                    "summary": "A resolve_hold command was retrieved but could not be enacted.",
                    "cause": "The command's decision was not 'approved' or 'denied'.",
                    "retryable": False,
                    "recommended_next_steps": [
                        "Resubmit resolve_hold with decision set to approved or denied.",
                        "Treat this hold as still awaiting a valid decision.",
                    ],
                },
            )
            continue
        reason = parameters.get("reason")
        reason = reason if isinstance(reason, str) and reason else None
        resolved_token = enactment._held_token
        enactment._held_token = None
        emit(
            "control",
            ControlCommand.create(
                ControlAction.RESOLVE_HOLD,
                reason_code=_reason_code(command),
                hold_token=resolved_token,
                decision=decision,
                reason=reason,
            ).to_event_data(),
        )
        return decision, str(getattr(command, "command_id", "")), reason
    return None


def _apply_pause_intent(
    enactment: "_ControlEnactment", command: Any | None, emit: Callable[[str, dict[str, Any]], None]
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
        if enactment._paused_by is not None:
            return None
        enactment._paused_by = command_id
        emit(
            "control",
            ControlCommand.create(
                ControlAction.PAUSE, reason_code=_reason_code(command)
            ).to_event_data(),
        )
        return None
    if enactment._paused_by is None:
        return None
    enactment._paused_by = None
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
    enactment: "_ControlEnactment", command: Any, emit: Callable[[str, dict[str, Any]], None]
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
    enactment._budget_kind = kind
    enactment._budget_limit = float(limit)
    enactment._budget_command_id = str(getattr(command, "command_id", ""))
    emit(
        "control",
        ControlCommand.create(
            ControlAction.SET_BUDGET,
            reason_code=_reason_code(command),
            budget_kind=kind,
            limit=limit,
        ).to_event_data(),
    )


def _surface_inject(
    command: Any, emit: Callable[[str, dict[str, Any]], None]
) -> str | None:
    """Records injected content in the trace. Returns its ``command_id``.

    This is the one action whose payload is **operator-supplied free
    text**, and the security property it has to hold is narrow and
    absolute: *the content is data that gets displayed, never data this
    loop parses for instructions*.

    How that is achieved is by construction rather than by filtering:

    - **Nothing reads the content.** The only value this loop ever
      dispatches on is ``command.action``, which the gateway derived from
      its own protobuf enum. Content shaped to look like a control
      directive -- ``action=stop``, a plausible ``command_id``, a
      ``status`` transition, an instruction addressed to a model -- takes
      exactly the same path as any other string, because there is no code
      path that would treat it differently. There is deliberately no
      sanitiser here: a sanitiser implies the content is on a path where
      it could matter, and the fix for that is to have no such path.
    - **It is surfaced as a ``control`` event, not a message.** A
      ``message`` event has a ``role``, and any role this content could be
      given (``system``, ``user``, ``assistant``) is a claim about
      authority it does not have. A ``control`` event under the agent's
      own actor says exactly what happened -- a control command was
      received -- and nothing more.
    - **The untrusted marking is re-stamped locally.** The classification
      is rebuilt by ``ControlCommand.create(INJECT, ...)``, which sets
      ``content_classification: "untrusted"`` itself, so the marking
      cannot be omitted or downgraded by what arrived on the wire. The
      wire value is *also* required to be ``untrusted``: a command that
      claims anything else violates the contract the gateway enforces on
      the way in, and is refused rather than accepted with a corrected
      label.
    - **It never touches the prompt.** ``prompt_ref`` is computed at
      ``turn_start``, before this runs, from the caller's own prompt.
      There is no merge step for content to be folded into.

    The turn is **not** halted. After the content is recorded the turn
    proceeds and completes normally, which is what distinguishes `inject`
    from every other action here.
    """
    parameters = getattr(command, "parameters", None)
    content = parameters.get("content") if isinstance(parameters, dict) else None
    classification = (
        parameters.get("content_classification") if isinstance(parameters, dict) else None
    )
    oversize = False
    if isinstance(content, str):
        try:
            oversize = len(content.encode("utf-8")) > MAX_UNTRUSTED_CONTROL_CONTENT_BYTES
        except UnicodeEncodeError:
            content = None
    if (
        not isinstance(content, str)
        or not content
        or classification != "untrusted"
        or oversize
    ):
        emit(
            "error",
            {
                "code": "REFERENCE_INJECT_CONTENT_REFUSED",
                "summary": "Injected content was retrieved but could not be surfaced.",
                "cause": "The command's content or content_classification did not satisfy the untrusted-content contract.",
                "retryable": False,
                "recommended_next_steps": [
                    "Resubmit the injection with non-empty UTF-8 content under 32 KiB.",
                    "Treat this turn as not having received the content.",
                ],
            },
        )
        return None
    try:
        emit(
            "control",
            ControlCommand.create(
                ControlAction.INJECT,
                reason_code=_reason_code(command),
                content=content,
            ).to_event_data(),
        )
    except Exception:
        # Event validation refuses `data` containing high-confidence
        # secret-like material, and injected content is exactly the field
        # an operator could paste a credential into. Refusing is right;
        # crashing the agent is not, and neither is echoing the rejected
        # text into an error event to explain why. Nothing about the
        # content reaches this diagnostic.
        emit(
            "error",
            {
                "code": "REFERENCE_INJECT_CONTENT_REFUSED",
                "summary": "Injected content was retrieved but could not be surfaced.",
                "cause": "The content could not be recorded as a validated untrusted-content control event.",
                "retryable": False,
                "recommended_next_steps": [
                    "Resubmit the injection without material the event contract refuses to record.",
                    "Treat this turn as not having received the content.",
                ],
            },
        )
        return None
    return str(getattr(command, "command_id", ""))


def _budget_exceeded(enactment: "_ControlEnactment") -> str | None:
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
    if enactment._budget_limit is None:
        return None
    used = enactment._used_tokens if enactment._budget_kind == "tokens" else enactment._used_cost
    if used <= enactment._budget_limit:
        return None
    return enactment._budget_command_id or ""
