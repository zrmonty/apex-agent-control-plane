"""Control-channel polling, dispatch, and enactment state for the reference loop.

Split out of ``reference_runtime.py``. :class:`ReferenceReasonActLoop` is
dominated by one large class, and Python does not let a single class's
methods be split across files the way a module can be split by concern.
What *is* cleanly separable is the concern itself: everything that touches
the out-of-band control channel -- polling it, acknowledging what was
enacted, and dispatching ``stop``/``pause``/``resume``/``set_budget``/
``inject``/``resolve_hold`` -- along with every piece of state that goes
with it (the poller handle, pause state, the budget ceiling and running
usage totals, the current hold, and the bounded at-least-once dedup set).
None of it depends on the turn-loop mechanics (event emission, prompt
handling, child-agent spawning) that stay on
:class:`~apex_sdk.reference_runtime.ReferenceReasonActLoop`, which owns one
:class:`_ControlEnactment` instance and forwards to it -- composition rather
than an arbitrary line-count chop that would split one cohesive class's
state across files.

The individual action handlers (``pause``/``resume``, ``set_budget``,
``inject``, and the budget-breach check) are themselves further split into
``_reference_control_actions.py`` -- see that module's docstring -- because
even this delegate is long enough on its own that folding them back in here
would defeat the point of the split.

See :class:`~apex_sdk.reference_runtime.ReferenceReasonActLoop`'s docstring
for the enactment order this implements and why it is that order; this
module implements the mechanism, not the policy narrative.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable

from .control import ControlAction, ControlCommand
from ._reference_control_actions import (
    _apply_budget,
    _apply_pause_intent,
    _apply_resolve_hold,
    _budget_exceeded,
    _surface_inject,
)
from ._reference_helpers import _reason_code, _uuid7

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


class _ControlEnactment:
    """Owns one loop's control poller, and every piece of enactment state.

    Constructed once per :class:`ReferenceReasonActLoop` and held for the
    life of the instance -- paused-ness, the budget ceiling, and the
    enacted-command dedup set are run-lifetime state, not per-turn state, for
    the same reasons documented on the owning class.
    """

    def __init__(self, control: Any | None) -> None:
        # Any object with a `poll(*, max_commands=...)` returning something
        # with a `.commands` sequence: the real `GrpcControlTransport`, an
        # `InMemoryControlPoller`, or a future subscription-based client.
        # Neither this class nor the loop that owns it imports the transport,
        # so the SDK still works with no gRPC stack installed.
        self._control = control
        self._paused_by: str | None = None
        self._budget_kind: str | None = None
        self._budget_limit: float | None = None
        self._budget_command_id: str | None = None
        self._used_tokens = 0
        self._used_cost = 0.0
        # The `hold_token` this loop is waiting on, or `None`. Single-slot,
        # the same model `_paused_by`/the budget ceiling already use: only one
        # hold can be in force on this loop at a time.
        self._held_token: str | None = None
        # Insertion-ordered set. `dict` rather than `set` because eviction has
        # to be oldest-first to be bounded in a useful way.
        self._enacted: dict[str, None] = {}

    # -- observable state, for a harness driving many turns -----------------

    @property
    def paused_by(self) -> str | None:
        """The ``command_id`` of the ``pause`` in force, or ``None``."""
        return self._paused_by

    @property
    def held_token(self) -> str | None:
        """The ``hold_token`` this loop is currently waiting on, or ``None``."""
        return self._held_token

    def enter_hold(self) -> str:
        """Suspends the next tool call pending an operator decision.

        Generates and records this loop's ``hold_token`` locally -- the
        identifier a later ``resolve_hold`` command must carry to unblock it.
        Both [[Human-in-the-Loop Approvals]] (blocking mode) and
        [[Defense-Evasion Interception]] (the hold tier) describe the agent
        itself minting this identifier when it enters the held state, rather
        than receiving one from the gateway, and this mirrors that.

        Deciding *when* to call this -- a risk score crossing a threshold, a
        ruleset match on generated content -- is the client-side
        interception point those two designs own and is deliberately not
        built here; this loop only owns getting the operator's decision back
        to a hold once something else has decided to start one, the delivery
        primitive both designs are missing.

        Calling this while already held replaces the previous token: only
        one hold can be in force on this loop at a time, the same
        single-slot model ``pause``/``set_budget`` already use for "the
        pause/ceiling in force".

        Generated with :func:`_uuid7`, the same generator every other
        identifier in this loop uses (``run_id``, ``trace_id``, event ids).
        Not merely for consistency: the event-data secret-policy heuristic
        (``validation.py``'s ``_encoded_secret``) treats a bare hex string of
        this length as possibly-encoded-secret-shaped outside a ``control``
        event, and a ``held``/``held_denied`` ``turn_end`` carries this token
        in a non-``control`` event. A hyphenated UUID is exactly the shape
        ``command_id`` already passes through that same check safely.
        """
        self._held_token = _uuid7()
        return self._held_token

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

    def record_usage(self, tokens: int, cost: float) -> None:
        """Advances the running usage totals the budget check reads.

        Called once per turn, at the same point `run()` emits the turn's
        `llm` event -- see that call site for why the ordering there matters.
        This is the one piece of "loop mechanics" state that budget
        enforcement also needs to read, so it is owned here rather than on
        the loop, with this method as the one way the loop feeds it in.
        """
        self._used_tokens += tokens
        self._used_cost += cost

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

        Retrieval starts an at-least-once delivery lease. If the transport
        exposes ``acknowledge(command)``, the runtime acknowledges each
        recognised command after processing it. If that acknowledgement is
        lost, the gateway's redelivery fallback remains safe because enactment
        is idempotent per ``command_id`` (see :meth:`_first_sight`), and a
        ``stop`` cannot end an already-ended run twice.

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

        See :class:`~apex_sdk.reference_runtime.ReferenceReasonActLoop`'s
        class docstring for why the order below is the order.
        """
        stop: Any | None = None
        pause_intent: Any | None = None
        budgets: list[Any] = []
        injects: list[Any] = []
        resolves: list[Any] = []
        acknowledged: list[Any] = []
        for command in self._poll(emit):
            action = getattr(command, "action", None)
            if action == "stop":
                # Deliberately not subject to `_first_sight`: a redelivered
                # `stop` must still halt a loop that somehow kept running, and
                # there is no state to corrupt by enacting it twice.
                if stop is None:
                    stop = command
                acknowledged.append(command)
                continue
            command_id = str(getattr(command, "command_id", ""))
            if not command_id or not self._first_sight(command_id):
                # A redelivery of something already enacted. Ignoring it is
                # what makes at-least-once delivery safe here -- in
                # particular, a `resume` redelivered after a *later* `pause`
                # must not un-pause the agent.
                if action in ("pause", "resume", "set_budget", "inject", "resolve_hold"):
                    acknowledged.append(command)
                continue
            if action in ("pause", "resume"):
                pause_intent = command
                acknowledged.append(command)
            elif action == "set_budget":
                budgets.append(command)
                acknowledged.append(command)
            elif action == "inject":
                injects.append(command)
                acknowledged.append(command)
            elif action == "resolve_hold":
                resolves.append(command)
                acknowledged.append(command)
            # Any other action -- including one this SDK decodes as
            # "unspecified" because the gateway is newer than the client -- is
            # inert. A runtime only enacts what it recognises, which is also
            # why nothing here dispatches on anything but `action`, a value
            # the gateway derived from its own enum.

        if stop is not None:
            emit(
                "control",
                ControlCommand.create(
                    ControlAction.STOP, reason_code=_reason_code(stop)
                ).to_event_data(),
            )
            self._acknowledge(acknowledged, emit)
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
            _apply_budget(self, command, emit)
        injected = [
            command_id
            for command_id in (_surface_inject(command, emit) for command in injects)
            if command_id is not None
        ]
        if injected:
            extra["injected_command_ids"] = injected
        resolve_result = _apply_resolve_hold(self, resolves, emit)
        resumed_by = _apply_pause_intent(self, pause_intent, emit)
        if self._paused_by is not None:
            # Every turn a paused agent starts still has to *end*, or the
            # trace shows a turn that began and never finished -- the same
            # "looks like a crash" ambiguity a silent return would produce.
            # So the terminal event repeats every turn while the `control`
            # event announcing the pause is emitted exactly once, on the
            # transition. That is the documented answer to "does a paused
            # agent re-announce itself forever": no, but it does keep saying
            # honestly that it did nothing.
            self._acknowledge(acknowledged, emit)
            return (
                {"status": "paused", "control_command_id": self._paused_by, **extra},
                {},
                None,
            )
        exceeded = _budget_exceeded(self)
        if exceeded is not None:
            # The budget is why this turn ended, so it owns the terminal
            # event's `control_command_id` even on a turn that also resumed.
            self._acknowledge(acknowledged, emit)
            return ({"status": "budget_exceeded", **extra, "control_command_id": exceeded}, {}, None)
        if resolve_result is not None and resolve_result[0] == "denied":
            # Unblocked, but with a decision that means the held call must
            # not proceed -- ends this turn only, not the whole run, which is
            # what distinguishes a denied hold from a `stop`.
            _decision, resolved_command_id, resolved_reason = resolve_result
            denied: dict[str, Any] = {
                "status": "held_denied",
                "control_command_id": resolved_command_id,
                **extra,
            }
            if resolved_reason is not None:
                denied["hold_reason"] = resolved_reason
            self._acknowledge(acknowledged, emit)
            return (denied, {}, None)
        if self._held_token is not None:
            # Still waiting: either nothing in this poll resolved the hold in
            # force, or nothing has resolved it since `enter_hold` was called.
            # Repeats every turn exactly as a standing `pause` does.
            self._acknowledge(acknowledged, emit)
            return (
                {"status": "held", "hold_token": self._held_token, **extra},
                {},
                None,
            )
        if resolve_result is not None:
            extra["control_command_id"] = resolve_result[1]
        if resumed_by is not None:
            extra["control_command_id"] = resumed_by
        self._acknowledge(acknowledged, emit)
        return (None, extra, resumed_by)

    def _acknowledge(
        self,
        commands: Sequence[Any],
        emit: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Settles processed gateway deliveries without making ACK fatal."""
        acknowledge = getattr(self._control, "acknowledge", None)
        if not callable(acknowledge):
            return
        for command in commands:
            try:
                accepted = acknowledge(command)
            except Exception:  # noqa: BLE001 - delivery remains safe to retry
                emit(
                    "error",
                    {
                        "code": "CONTROL_ACK_UNAVAILABLE",
                        "summary": "A processed control command could not be acknowledged.",
                        "cause": "The runtime will rely on the gateway's bounded redelivery fallback.",
                        "retryable": True,
                    },
                )
                continue
            if not accepted:
                emit(
                    "error",
                    {
                        "code": "CONTROL_ACK_REJECTED",
                        "summary": "The control gateway did not accept the command acknowledgement.",
                        "cause": "The command was processed locally but may be redelivered by the gateway.",
                        "retryable": True,
                    },
                )
