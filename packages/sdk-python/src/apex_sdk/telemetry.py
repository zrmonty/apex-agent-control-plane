"""One-way mapping from Apex's canonical events to OTel attributes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import TelemetryMappingError
from .validation import EVENT_TYPES, SAFE_IDENTIFIER


_OPERATIONS = {"llm": "chat", "tool": "execute_tool"}


def to_otel_attributes(event: Mapping[str, Any]) -> dict[str, str | int | tuple[str, ...]]:
    """Map stable Apex identity and supported GenAI attributes for export."""
    correlation = {key: event[key] for key in ("trace_id", "run_id") if isinstance(event, Mapping) and isinstance(event.get(key), str)}
    try:
        if not isinstance(event, Mapping):
            raise TypeError("event must be an object")
        scope = event["scope"]
        version = event["version"]
        data = event["data"]
        if not all(isinstance(value, Mapping) for value in (scope, version, data)):
            raise TypeError("event sections must be objects")
        identifiers = [event["agent_id"], event["run_id"], event["trace_id"], scope["workspace_id"], scope["namespace_id"], version["agent_code"], version["prompt"]]
        groups = scope["agent_group_ids"]
        if not isinstance(groups, list) or not all(isinstance(value, str) and SAFE_IDENTIFIER.fullmatch(value) for value in [*identifiers, *groups]):
            raise TypeError("telemetry identifiers must be safe strings")
        event_type = event["type"]
        if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
            raise TypeError("event type is unsupported")
        attributes: dict[str, str | int | tuple[str, ...]] = {
            "apex.agent.id": event["agent_id"],
            "apex.run.id": event["run_id"],
            "apex.trace.id": event["trace_id"],
            "apex.workspace.id": scope["workspace_id"],
            "apex.namespace.id": scope["namespace_id"],
            "apex.agent_group.ids": tuple(groups),
            "apex.version.agent_code": version["agent_code"],
            "apex.version.prompt": version["prompt"],
            "gen_ai.operation.name": _OPERATIONS.get(event_type, event_type),
        }
        if event_type == "llm":
            provider, model = data["provider"], data["model"]
            input_tokens, output_tokens = data["input_tokens"], data["output_tokens"]
            if not all(isinstance(value, str) and SAFE_IDENTIFIER.fullmatch(value) for value in (provider, model)) or not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (input_tokens, output_tokens)):
                raise TypeError("LLM telemetry fields are invalid")
            attributes.update({"gen_ai.provider.name": provider, "gen_ai.request.model": model, "gen_ai.usage.input_tokens": input_tokens, "gen_ai.usage.output_tokens": output_tokens})
        return attributes
    except (KeyError, TypeError) as exc:
        raise TelemetryMappingError(correlation=correlation) from exc
