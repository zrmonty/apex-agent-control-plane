"""Small, standalone helpers used by the reference reason-act loop.

Pure functions with no dependency on :class:`ReferenceReasonActLoop`,
:class:`_ControlEnactment`, or any instance state -- kept in one place so both
own the identifier/validation and UUIDv7 generation rules exactly once rather
than each re-deriving them.
"""

from __future__ import annotations

import math
import re
import secrets
import time
from typing import Any
from uuid import UUID

from .control import ControlValidationError

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


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


def _reason_code(command: Any) -> str | None:
    """The command's ``reason_code``, or ``None`` if it is not safe to echo.

    Operator-supplied text. It must never be able to make a command
    un-enactable by failing event validation on the way out.
    """
    reason_code = getattr(command, "reason_code", None)
    if reason_code is None:
        return None
    return reason_code if _SAFE_IDENTIFIER.fullmatch(str(reason_code)) else None
