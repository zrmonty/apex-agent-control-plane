"""Cooperative v1 control commands carried in canonical control events."""

from __future__ import annotations

import copy
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .errors import ApexError
from .validation import (
    MAX_CONTROL_BUDGET_LIMIT,
    MAX_HOLD_REASON_BYTES,
    MAX_UNTRUSTED_CONTROL_CONTENT_BYTES,
    SAFE_IDENTIFIER,
)


class ControlAction(StrEnum):
    STOP = "stop"
    PAUSE = "pause"
    RESUME = "resume"
    INJECT = "inject"
    SET_BUDGET = "set_budget"
    #: Delivers an operator's approve/deny decision for a specific hold a
    #: waiting agent generated locally when it suspended a tool call -- the
    #: shared delivery primitive both Human-in-the-Loop Approvals' blocking
    #: mode and Defense-Evasion Interception's hold tier need to get a
    #: decision back to the agent. See ``resolve_hold`` handling in
    #: ``apex_sdk.reference_runtime.ReferenceReasonActLoop``.
    RESOLVE_HOLD = "resolve_hold"


class ControlValidationError(ApexError):
    code = "CONTROL_COMMAND_INVALID"
    category = "control"
    safe_message = "The control command is not valid."


@dataclass(frozen=True)
class ControlCommand:
    action: ControlAction
    enforcement: str
    reason_code: str | None
    parameters: dict[str, Any]

    @classmethod
    def create(
        cls,
        action: ControlAction,
        *,
        enforcement: str = "cooperative",
        reason_code: str | None = None,
        content: str | None = None,
        budget_kind: str | None = None,
        limit: int | float | None = None,
        hold_token: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
    ) -> "ControlCommand":
        if not isinstance(action, ControlAction):
            raise ControlValidationError("control action must be a ControlAction value")
        if enforcement != "cooperative":
            raise ControlValidationError("v1 controls are cooperative")
        if reason_code is not None and (not isinstance(reason_code, str) or not SAFE_IDENTIFIER.fullmatch(reason_code)):
            raise ControlValidationError("reason_code must be a safe identifier or null")
        if action is ControlAction.RESUME and reason_code is not None:
            raise ControlValidationError("resume does not accept a reason_code")
        if action is ControlAction.INJECT:
            if not isinstance(content, str) or not content:
                raise ControlValidationError("inject requires content")
            try:
                if len(content.encode("utf-8")) > MAX_UNTRUSTED_CONTROL_CONTENT_BYTES:
                    raise ControlValidationError("inject content must not exceed 32 KiB")
            except UnicodeEncodeError as exc:
                raise ControlValidationError("inject content must be valid UTF-8") from exc
            if budget_kind is not None or limit is not None or hold_token is not None or decision is not None or reason is not None:
                raise ControlValidationError("inject does not accept budget parameters")
            return cls(action, enforcement, reason_code, {"content": content, "content_classification": "untrusted"})
        if action is ControlAction.SET_BUDGET:
            if budget_kind not in {"tokens", "cost"}:
                raise ControlValidationError("set_budget requires budget_kind of tokens or cost")
            if not isinstance(limit, (int, float)) or isinstance(limit, bool) or not math.isfinite(limit) or limit <= 0 or limit > MAX_CONTROL_BUDGET_LIMIT:
                raise ControlValidationError("set_budget requires a positive limit that is finite and no greater than 1e15")
            if content is not None or hold_token is not None or decision is not None or reason is not None:
                raise ControlValidationError("set_budget does not accept content")
            return cls(action, enforcement, reason_code, {"budget_kind": budget_kind, "limit": limit})
        if action is ControlAction.RESOLVE_HOLD:
            if not isinstance(hold_token, str) or not hold_token or not SAFE_IDENTIFIER.fullmatch(hold_token):
                raise ControlValidationError("resolve_hold requires a hold_token that is a safe identifier")
            if decision not in ("approved", "denied"):
                raise ControlValidationError("resolve_hold requires decision of approved or denied")
            if reason is not None:
                if not isinstance(reason, str) or not reason:
                    raise ControlValidationError("resolve_hold reason must be a non-empty string or null")
                try:
                    if len(reason.encode("utf-8")) > MAX_HOLD_REASON_BYTES:
                        raise ControlValidationError("resolve_hold reason must not exceed 8 KiB")
                except UnicodeEncodeError as exc:
                    raise ControlValidationError("resolve_hold reason must be valid UTF-8") from exc
            if content is not None or budget_kind is not None or limit is not None:
                raise ControlValidationError("resolve_hold does not accept inject or budget parameters")
            return cls(action, enforcement, reason_code, {"hold_token": hold_token, "decision": decision, "reason": reason})
        if content is not None or budget_kind is not None or limit is not None or hold_token is not None or decision is not None or reason is not None:
            raise ControlValidationError(f"{action.value} does not accept parameters")
        return cls(action, enforcement, reason_code, {})

    def to_event_data(self) -> dict[str, Any]:
        return {"action": self.action.value, "enforcement": self.enforcement, "reason_code": self.reason_code, "parameters": copy.deepcopy(self.parameters)}
