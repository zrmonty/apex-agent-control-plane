import pytest

from apex_sdk import TelemetryMappingError
from apex_sdk.telemetry import to_otel_attributes


def test_llm_event_maps_apex_identity_and_genai_usage() -> None:
    event = {
        "type": "llm",
        "agent_id": "researcher",
        "run_id": "run-1",
        "trace_id": "trace-1",
        "scope": {"workspace_id": "acme", "namespace_id": "production", "agent_group_ids": ["research"]},
        "version": {"agent_code": "v1", "prompt": "prompt-1", "model": "gpt-5"},
        "data": {"input_tokens": 12, "output_tokens": 34, "provider": "openai", "model": "gpt-5"},
    }

    attributes = to_otel_attributes(event)

    assert attributes == {
        "apex.agent.id": "researcher",
        "apex.run.id": "run-1",
        "apex.trace.id": "trace-1",
        "apex.workspace.id": "acme",
        "apex.namespace.id": "production",
        "apex.agent_group.ids": ("research",),
        "apex.version.agent_code": "v1",
        "apex.version.prompt": "prompt-1",
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": "openai",
        "gen_ai.request.model": "gpt-5",
        "gen_ai.usage.input_tokens": 12,
        "gen_ai.usage.output_tokens": 34,
    }


def test_non_llm_event_keeps_apex_fields_without_genai_usage() -> None:
    event = {
        "type": "tool",
        "agent_id": "worker",
        "run_id": "run-2",
        "trace_id": "trace-2",
        "scope": {"workspace_id": "acme", "namespace_id": "production", "agent_group_ids": []},
        "version": {"agent_code": "v2", "prompt": "prompt-2", "model": "gpt-5"},
        "data": {"name": "search"},
    }

    attributes = to_otel_attributes(event)

    assert attributes["gen_ai.operation.name"] == "execute_tool"
    assert "gen_ai.usage.input_tokens" not in attributes
    assert attributes["apex.agent_group.ids"] == ()


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        {"type": "llm", "agent_id": "agent", "run_id": "run", "trace_id": "trace", "scope": {"workspace_id": "workspace", "namespace_id": "namespace", "agent_group_ids": []}, "version": {"agent_code": "v1", "prompt": "p1", "model": "gpt-5"}, "data": {"provider": "authorization=Bearer top-secret", "model": "gpt-5", "input_tokens": 1, "output_tokens": 1}},
        {"type": "llm", "agent_id": "agent", "run_id": "run", "trace_id": "trace", "scope": {"workspace_id": "workspace", "namespace_id": "namespace", "agent_group_ids": ["unsafe\nidentifier"]}, "version": {"agent_code": "v1", "prompt": "p1", "model": "gpt-5"}, "data": {"provider": "openai", "model": "gpt-5", "input_tokens": 1, "output_tokens": 1}},
    ],
)
def test_mapping_rejects_non_object_and_unsafe_telemetry_attributes(event: object) -> None:
    with pytest.raises(TelemetryMappingError) as raised:
        to_otel_attributes(event)  # type: ignore[arg-type]

    assert "top-secret" not in str(raised.value)
