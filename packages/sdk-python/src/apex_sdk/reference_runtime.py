"""Small deterministic reason-act loop used to exercise the Phase 0 contract."""

from __future__ import annotations

import secrets
import hashlib
import re
import time
from datetime import UTC, datetime
from typing import Any, Callable
from uuid import UUID

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
    """Emit a readable start/LLM/tool/message/end trace through an observer."""

    def __init__(self, observer: BoundedObserver, *, agent_id: str, scope: dict[str, Any], version: dict[str, str]) -> None:
        self._observer = observer
        self._agent_id = agent_id
        self._scope = scope
        self._version = version

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

        prompt_ref = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        emit("turn_start", {"prompt_ref": prompt_ref})
        emit("llm", {"provider": "reference", "model": self._version["model"], "input_tokens": 0, "output_tokens": 0})
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
