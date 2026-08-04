from __future__ import annotations

import pytest

from apex_sdk import (
    AgentTemplateError,
    CONTROL_FRAMEWORK_MAP,
    GOLD_STANDARD_CONTROLS,
    HIGH_IMPACT_CONTROLS,
    TEMPLATE_VERSION,
    assess_agent_template,
    control_catalog,
    control_spec,
    gold_standard_controls,
    gold_standard_manifest,
    require_compliant_template,
)
from apex_sdk.template import CONTROL_CATALOG, ControlCategory


def manifest(**overrides: object) -> dict[str, object]:
    base = gold_standard_manifest("reference-agent")
    if "controls" in overrides:
        controls = dict(base["controls"])  # type: ignore[arg-type]
        controls.update(overrides.pop("controls"))  # type: ignore[arg-type]
        base["controls"] = controls
    base.update(overrides)  # type: ignore[arg-type]
    return base


def test_catalog_is_single_source_of_truth() -> None:
    assert len(CONTROL_CATALOG) == 10
    assert GOLD_STANDARD_CONTROLS == tuple(spec.name for spec in CONTROL_CATALOG)
    assert set(CONTROL_FRAMEWORK_MAP) == set(GOLD_STANDARD_CONTROLS)
    assert HIGH_IMPACT_CONTROLS == frozenset(s.name for s in CONTROL_CATALOG if s.high_impact)
    assert all(spec.frameworks for spec in CONTROL_CATALOG)
    assert all(isinstance(spec.category, ControlCategory) for spec in CONTROL_CATALOG)
    assert control_catalog() is CONTROL_CATALOG
    assert control_spec("secret_redaction") is not None
    assert control_spec("not-a-control") is None
    assert control_spec("secret_redaction").as_dict()["category"] == "data_safety"


def test_gold_standard_manifest_builder_and_helpers() -> None:
    full = gold_standard_manifest("home-demo")
    assert full["template_version"] == TEMPLATE_VERSION
    assert full["agent_code"] == "home-demo"
    assert full["controls"] == gold_standard_controls(enabled=True)
    assert assess_agent_template(full).compliant is True

    partial = gold_standard_manifest(
        "partial-agent",
        controls={"secret_redaction": True, "tool_allowlist": True},
    )
    assessment = assess_agent_template(partial)
    assert assessment.compliant is False
    assert partial["controls"]["secret_redaction"] is True
    assert partial["controls"]["scope_bound_identity"] is False

    with pytest.raises(AgentTemplateError, match="safe identifier"):
        gold_standard_manifest("../bad")
    with pytest.raises(AgentTemplateError, match="unsupported controls"):
        gold_standard_manifest("agent", controls={"not_real": True})


def test_gold_standard_template_is_compliant_and_event_safe() -> None:
    assessment = assess_agent_template(manifest())
    assert assessment.compliant is True
    assert assessment.score == 1.0
    assert assessment.severity == "info"
    assert assessment.security_finding() is None
    assert assessment.satisfied_controls == GOLD_STANDARD_CONTROLS
    assert assessment.high_impact_gaps == ()
    assert assessment.categories_with_gaps == ()
    data = assessment.event_data()
    assert data["assessment"] == "agent_template"
    assert data["satisfied_control_count"] == 10
    assert data["high_impact_gaps"] == []
    assert assessment.as_dict()["control_status"]["secret_redaction"] == "satisfied"
    assert require_compliant_template(manifest()) is not None


def test_missing_controls_create_redacted_high_finding() -> None:
    assessment = assess_agent_template(manifest(controls={"secret_redaction": False, "tool_allowlist": True}))
    assert assessment.compliant is False
    assert assessment.severity == "high"
    assert "secret_redaction" in assessment.high_impact_gaps
    assert "data_safety" in assessment.categories_with_gaps
    assert assessment.control_status()["secret_redaction"] == "missing"
    finding = assessment.security_finding()
    assert finding is not None
    assert "secret_redaction" in finding["missing_controls"]
    assert finding["high_impact_gaps"]
    assert "manifest" not in str(finding).lower()
    with pytest.raises(AgentTemplateError, match="noncompliant"):
        assessment.require_compliant()


def test_medium_severity_when_only_low_impact_gaps() -> None:
    # Only non-high-impact telemetry controls disabled.
    controls = gold_standard_controls(enabled=True)
    controls["validated_hash_chain"] = False
    controls["lifecycle_events"] = False
    assessment = assess_agent_template(
        {"template_version": TEMPLATE_VERSION, "agent_code": "agent", "controls": controls}
    )
    assert assessment.compliant is False
    assert assessment.severity == "medium"
    assert assessment.high_impact_gaps == ()
    assert "telemetry" in assessment.categories_with_gaps


def test_invalid_control_type_is_reported_without_raw_value() -> None:
    assessment = assess_agent_template(manifest(controls={"scope_bound_identity": "yes"}))
    assert assessment.invalid_controls == ("scope_bound_identity",)
    assert assessment.severity == "high"
    assert assessment.event_data()["invalid_control_count"] == 1
    assert assessment.control_status()["scope_bound_identity"] == "invalid"
    # Invalid controls do not inflate the satisfied score.
    assert assessment.score < 1.0


def test_fingerprint_is_stable_and_changes_with_gaps() -> None:
    a = assess_agent_template(manifest())
    b = assess_agent_template(manifest())
    assert a.fingerprint == b.fingerprint
    c = assess_agent_template(manifest(controls={"secret_redaction": False}))
    assert c.fingerprint != a.fingerprint


@pytest.mark.parametrize("bad", [None, [], "text", {"template_version": TEMPLATE_VERSION}])
def test_malformed_manifest_is_rejected(bad: object) -> None:
    with pytest.raises(AgentTemplateError):
        assess_agent_template(bad)  # type: ignore[arg-type]


def test_unknown_fields_and_unsafe_agent_code_are_rejected() -> None:
    with pytest.raises(AgentTemplateError, match="unsupported fields"):
        assess_agent_template({**manifest(), "prompt": "do not retain"})
    with pytest.raises(AgentTemplateError, match="agent_code"):
        assess_agent_template({**manifest(), "agent_code": "../agent"})
    with pytest.raises(AgentTemplateError, match="template_version"):
        assess_agent_template({**manifest(), "template_version": "apex-agent-template.v0"})
    with pytest.raises(AgentTemplateError, match="controls object"):
        assess_agent_template(
            {"template_version": TEMPLATE_VERSION, "agent_code": "agent", "controls": ["nope"]}
        )
    with pytest.raises(AgentTemplateError, match="field names must be strings"):
        assess_agent_template({1: "x"})  # type: ignore[dict-item]
    with pytest.raises(AgentTemplateError, match="control names must be strings"):
        assess_agent_template(
            {
                "template_version": TEMPLATE_VERSION,
                "agent_code": "agent",
                "controls": {1: True},  # type: ignore[dict-item]
            }
        )
    with pytest.raises(AgentTemplateError, match="boolean"):
        gold_standard_manifest("agent", controls={"secret_redaction": "yes"})  # type: ignore[dict-item]
    with pytest.raises(AgentTemplateError, match="boolean declarations"):
        gold_standard_manifest("agent", controls=["secret_redaction"])  # type: ignore[arg-type]
