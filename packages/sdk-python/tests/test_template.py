from __future__ import annotations

import pytest

from apex_sdk import AgentTemplateError, assess_agent_template
from apex_sdk.template import GOLD_STANDARD_CONTROLS, TEMPLATE_VERSION


def manifest(**overrides: object) -> dict[str, object]:
    controls = {name: True for name in GOLD_STANDARD_CONTROLS}
    controls.update(overrides.pop("controls", {}))
    return {"template_version": TEMPLATE_VERSION, "agent_code": "reference-agent", "controls": controls, **overrides}


def test_gold_standard_template_is_compliant_and_event_safe() -> None:
    assessment = assess_agent_template(manifest())
    assert assessment.compliant is True
    assert assessment.score == 1.0
    assert assessment.security_finding() is None
    assert assessment.event_data()["assessment"] == "agent_template"


def test_missing_controls_create_redacted_high_finding() -> None:
    assessment = assess_agent_template(manifest(controls={"secret_redaction": False, "tool_allowlist": True}))
    assert assessment.compliant is False
    assert assessment.severity == "high"
    finding = assessment.security_finding()
    assert finding is not None
    assert "secret_redaction" in finding["missing_controls"]
    assert "manifest" not in str(finding).lower()


def test_invalid_control_type_is_reported_without_raw_value() -> None:
    assessment = assess_agent_template(manifest(controls={"scope_bound_identity": "yes"}))
    assert assessment.invalid_controls == ("scope_bound_identity",)
    assert assessment.severity == "high"
    assert assessment.event_data()["invalid_control_count"] == 1


@pytest.mark.parametrize("bad", [None, [], "text", {"template_version": TEMPLATE_VERSION}])
def test_malformed_manifest_is_rejected(bad: object) -> None:
    with pytest.raises(AgentTemplateError):
        assess_agent_template(bad)  # type: ignore[arg-type]


def test_unknown_fields_and_unsafe_agent_code_are_rejected() -> None:
    with pytest.raises(AgentTemplateError):
        assess_agent_template({**manifest(), "prompt": "do not retain"})
    with pytest.raises(AgentTemplateError):
        assess_agent_template({**manifest(), "agent_code": "../agent"})
