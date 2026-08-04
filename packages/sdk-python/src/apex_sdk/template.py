"""Deterministic gold-standard agent-template compliance assessment.

The agent template is a bounded, non-secret capability declaration that every
connected agent should publish before admission. It is intentionally small and
declarative: prompts, completions, credentials, tool output, and source code
must never appear in the manifest.

The ten controls are implementation evidence mapped to SOC 2, HIPAA, SEC
records, and FedRAMP-oriented safeguards. They are not a certification claim.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .errors import ConfigurationError

TEMPLATE_VERSION = "apex-agent-template.v1"
SAFE_NAME = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_MANIFEST_FIELDS = frozenset({"template_version", "agent_code", "controls"})
_SCORE_BASIS = "gold_standard_control_count"


class ControlCategory(str, Enum):
    """Operator-facing grouping for gold-standard controls."""

    IDENTITY = "identity"
    TELEMETRY = "telemetry"
    DATA_SAFETY = "data_safety"
    ISOLATION = "isolation"
    DIAGNOSTICS = "diagnostics"


@dataclass(frozen=True, slots=True)
class ControlSpec:
    """One gold-standard control: identity, impact, summary, and framework tags."""

    name: str
    category: ControlCategory
    high_impact: bool
    summary: str
    frameworks: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "high_impact": self.high_impact,
            "summary": self.summary,
            "frameworks": list(self.frameworks),
        }


# Single source of truth. Order is the public assessment and fingerprint order.
CONTROL_CATALOG: tuple[ControlSpec, ...] = (
    ControlSpec(
        name="scope_bound_identity",
        category=ControlCategory.IDENTITY,
        high_impact=True,
        summary="Workload identity is bound to an exact workspace/namespace scope before work begins.",
        frameworks=("SOC2-CC6", "HIPAA-164.312(d)", "FedRAMP-AC-2"),
    ),
    ControlSpec(
        name="short_lived_credentials",
        category=ControlCategory.IDENTITY,
        high_impact=True,
        summary="Credentials and tokens are short-lived, rotatable, and never embedded in the agent image.",
        frameworks=("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-IA-5"),
    ),
    ControlSpec(
        name="validated_hash_chain",
        category=ControlCategory.TELEMETRY,
        high_impact=False,
        summary="Emitted events carry a validated prev_hash/event_hash chain using the Apex envelope contract.",
        frameworks=("SOC2-CC7", "SEC-17a-4", "FedRAMP-AU-10"),
    ),
    ControlSpec(
        name="bounded_event_capture",
        category=ControlCategory.TELEMETRY,
        high_impact=False,
        summary="Event capture is size-bounded (envelope and content caps) and rejects oversized payloads fail-closed.",
        frameworks=("SOC2-CC7", "HIPAA-164.312(b)", "FedRAMP-AU-2"),
    ),
    ControlSpec(
        name="lifecycle_events",
        category=ControlCategory.TELEMETRY,
        high_impact=False,
        summary="Each run emits turn_start and a terminal turn_end or error, plus material tool/model lifecycle events.",
        frameworks=("SOC2-CC7", "HIPAA-164.308(a)(1)", "FedRAMP-AU-2"),
    ),
    ControlSpec(
        name="secret_redaction",
        category=ControlCategory.DATA_SAFETY,
        high_impact=True,
        summary="Secrets and high-risk material are redacted or blocked before durable storage or egress.",
        frameworks=("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-SC-28"),
    ),
    ControlSpec(
        name="untrusted_content_taint_boundary",
        category=ControlCategory.DATA_SAFETY,
        high_impact=True,
        summary="External text (user input, tools, memory, control.inject) is treated as data, never as trusted instructions.",
        frameworks=("SOC2-CC6", "HIPAA-164.308(a)(5)", "FedRAMP-SI-10"),
    ),
    ControlSpec(
        name="tool_allowlist",
        category=ControlCategory.ISOLATION,
        high_impact=True,
        summary="Tools execute only from an explicit allowlist; unknown tools are denied by default.",
        frameworks=("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-AC-3"),
    ),
    ControlSpec(
        name="egress_denied_by_default",
        category=ControlCategory.ISOLATION,
        high_impact=True,
        summary="Network and data egress are denied by default and only opened through approved policy.",
        frameworks=("SOC2-CC6", "HIPAA-164.312(e)", "FedRAMP-SC-7"),
    ),
    ControlSpec(
        name="stable_redacted_diagnostics",
        category=ControlCategory.DIAGNOSTICS,
        high_impact=False,
        summary="Diagnostics use stable codes, safe summaries, and redacted correlation—never raw tokens or payloads.",
        frameworks=("SOC2-CC7", "HIPAA-164.312(b)", "FedRAMP-AU-3"),
    ),
)

GOLD_STANDARD_CONTROLS: tuple[str, ...] = tuple(spec.name for spec in CONTROL_CATALOG)
_CONTROL_BY_NAME: dict[str, ControlSpec] = {spec.name: spec for spec in CONTROL_CATALOG}
_GOLD_STANDARD_SET = frozenset(GOLD_STANDARD_CONTROLS)
HIGH_IMPACT_CONTROLS = frozenset(spec.name for spec in CONTROL_CATALOG if spec.high_impact)

# Evidence-oriented mappings only. Presence of a control does not establish
# certification or satisfy an organization's complete control framework.
CONTROL_FRAMEWORK_MAP: dict[str, tuple[str, ...]] = {
    spec.name: spec.frameworks for spec in CONTROL_CATALOG
}


class AgentTemplateError(ConfigurationError):
    code = "AGENT_TEMPLATE_INVALID"
    safe_message = "The agent template manifest is not valid."
    cause = "The template manifest must contain bounded, non-secret capability declarations."
    recommended_next_steps = (
        "Provide the required Apex template version and boolean control declarations.",
        "Do not include prompts, completions, credentials, or raw tool output in the manifest.",
        "Build a baseline with gold_standard_manifest(agent_code) and set only controls you implement.",
    )


@dataclass(frozen=True, slots=True)
class TemplateAssessment:
    """Result of assessing a non-secret capability manifest."""

    template_version: str
    agent_code: str
    compliant: bool
    score: float
    missing_controls: tuple[str, ...]
    invalid_controls: tuple[str, ...]
    fingerprint: str

    @property
    def severity(self) -> str:
        if self.compliant:
            return "info"
        high_impact_gap = HIGH_IMPACT_CONTROLS.intersection(self.missing_controls)
        if self.invalid_controls or high_impact_gap or len(self.missing_controls) >= 3:
            return "high"
        return "medium"

    @property
    def satisfied_controls(self) -> tuple[str, ...]:
        unsatisfied = set(self.missing_controls) | set(self.invalid_controls)
        return tuple(name for name in GOLD_STANDARD_CONTROLS if name not in unsatisfied)

    @property
    def high_impact_gaps(self) -> tuple[str, ...]:
        return tuple(name for name in GOLD_STANDARD_CONTROLS if name in HIGH_IMPACT_CONTROLS and name in self.missing_controls)

    @property
    def categories_with_gaps(self) -> tuple[str, ...]:
        """Distinct control categories that still have unsatisfied controls."""
        gaps = set(self.missing_controls) | set(self.invalid_controls)
        ordered: list[str] = []
        seen: set[str] = set()
        for spec in CONTROL_CATALOG:
            if spec.name in gaps and spec.category.value not in seen:
                seen.add(spec.category.value)
                ordered.append(spec.category.value)
        return tuple(ordered)

    def control_status(self) -> dict[str, str]:
        """Map each gold-standard control to satisfied | missing | invalid."""
        invalid = set(self.invalid_controls)
        missing = set(self.missing_controls)
        status: dict[str, str] = {}
        for name in GOLD_STANDARD_CONTROLS:
            if name in invalid:
                status[name] = "invalid"
            elif name in missing:
                status[name] = "missing"
            else:
                status[name] = "satisfied"
        return status

    def security_finding(self) -> dict[str, Any] | None:
        """Return a safe finding payload, omitting all manifest content."""
        if self.compliant:
            return None
        return {
            "type": "agent.template.noncompliant",
            "severity": self.severity,
            "confidence": "deterministic",
            "policy_decision": "require_approval",
            "detector": f"template/{self.template_version}",
            "fingerprint": self.fingerprint,
            "missing_controls": list(self.missing_controls),
            "invalid_controls": list(self.invalid_controls),
            "high_impact_gaps": list(self.high_impact_gaps),
            "categories_with_gaps": list(self.categories_with_gaps),
            "recommended_action": "quarantine_or_require_review",
        }

    def event_data(self) -> dict[str, Any]:
        """Return bounded metadata suitable for a `score` or `error` event."""
        return {
            "assessment": "agent_template",
            "template_version": self.template_version,
            "agent_code": self.agent_code,
            "compliant": self.compliant,
            "score_basis": _SCORE_BASIS,
            "score": self.score,
            "missing_control_count": len(self.missing_controls),
            "invalid_control_count": len(self.invalid_controls),
            "satisfied_control_count": len(self.satisfied_controls),
            "missing_controls": list(self.missing_controls),
            "invalid_controls": list(self.invalid_controls),
            "high_impact_gaps": list(self.high_impact_gaps),
            "categories_with_gaps": list(self.categories_with_gaps),
            "fingerprint": self.fingerprint,
        }

    def as_dict(self) -> dict[str, Any]:
        """Full assessment view for local operators (still free of secrets)."""
        return {
            **self.event_data(),
            "severity": self.severity,
            "control_status": self.control_status(),
            "satisfied_controls": list(self.satisfied_controls),
        }

    def require_compliant(self) -> TemplateAssessment:
        """Raise AgentTemplateError when the assessment is noncompliant."""
        if self.compliant:
            return self
        finding = self.security_finding() or {}
        raise AgentTemplateError(
            f"agent template is noncompliant (score={self.score}, "
            f"missing={len(self.missing_controls)}, invalid={len(self.invalid_controls)}, "
            f"fingerprint={finding.get('fingerprint', self.fingerprint)})"
        )


def control_catalog() -> tuple[ControlSpec, ...]:
    """Return the ordered gold-standard control catalog."""
    return CONTROL_CATALOG


def control_spec(name: str) -> ControlSpec | None:
    """Look up one control by name, or None if unknown."""
    return _CONTROL_BY_NAME.get(name)


def gold_standard_controls(*, enabled: bool = True) -> dict[str, bool]:
    """Return a full boolean control map for the current template version."""
    return {name: enabled for name in GOLD_STANDARD_CONTROLS}


def gold_standard_manifest(agent_code: str, *, controls: Mapping[str, bool] | None = None) -> dict[str, Any]:
    """Build a v1 capability manifest.

    When ``controls`` is omitted, every gold-standard control is declared true.
    Callers may pass a partial map; unspecified controls default to false so
    assessments stay explicit about gaps.
    """
    if not isinstance(agent_code, str) or not SAFE_NAME.fullmatch(agent_code):
        raise AgentTemplateError("agent_code must be a 1–256 character safe identifier")
    declared = gold_standard_controls(enabled=False)
    if controls is not None:
        if not isinstance(controls, Mapping):
            raise AgentTemplateError("controls must be an object of boolean declarations")
        unknown = set(controls) - _GOLD_STANDARD_SET
        if unknown:
            raise AgentTemplateError("agent template contains unsupported controls")
        for name, value in controls.items():
            if not isinstance(value, bool):
                raise AgentTemplateError("agent template control values must be booleans")
            declared[name] = value
    else:
        declared = gold_standard_controls(enabled=True)
    return {
        "template_version": TEMPLATE_VERSION,
        "agent_code": agent_code,
        "controls": declared,
    }


def _fingerprint(version: str, agent_code: str, missing: Iterable[str], invalid: Iterable[str]) -> str:
    # Ordered, ASCII-only material so the fingerprint is stable across platforms.
    material = f"{version}|{agent_code}|missing={','.join(missing)}|invalid={','.join(invalid)}"
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def assess_agent_template(manifest: Mapping[str, Any] | dict[str, Any]) -> TemplateAssessment:
    """Assess a non-secret capability manifest against the gold standard.

    Validation is fail-closed on structure. Assessment is deterministic: the
    same inputs always yield the same score, gaps, severity, and fingerprint.
    """
    if not isinstance(manifest, Mapping):
        raise AgentTemplateError("agent template must be an object")
    # Reject mapping subclasses that are not plain dicts of JSON-like data
    # only when keys are non-string (e.g. accidental int keys).
    if any(not isinstance(key, str) for key in manifest):
        raise AgentTemplateError("agent template field names must be strings")

    unknown_fields = set(manifest) - _MANIFEST_FIELDS
    if unknown_fields:
        raise AgentTemplateError("agent template contains unsupported fields")

    version = manifest.get("template_version")
    agent_code = manifest.get("agent_code")
    controls = manifest.get("controls")
    if version != TEMPLATE_VERSION:
        raise AgentTemplateError("agent template requires the supported template_version")
    if not isinstance(agent_code, str) or not SAFE_NAME.fullmatch(agent_code):
        raise AgentTemplateError("agent template requires a valid agent_code")
    if not isinstance(controls, Mapping):
        raise AgentTemplateError("agent template requires a controls object")
    if any(not isinstance(key, str) for key in controls):
        raise AgentTemplateError("agent template control names must be strings")
    if len(controls) > len(GOLD_STANDARD_CONTROLS):
        raise AgentTemplateError("agent template controls exceed the supported bounded set")

    unknown_controls = set(controls) - _GOLD_STANDARD_SET
    if unknown_controls:
        raise AgentTemplateError("agent template contains unsupported controls")

    invalid = tuple(sorted(name for name, value in controls.items() if not isinstance(value, bool)))
    # Absent or non-true declarations are unsatisfied (including explicit false).
    missing = tuple(
        name
        for name in GOLD_STANDARD_CONTROLS
        if name not in invalid and controls.get(name) is not True
    )
    satisfied = len(GOLD_STANDARD_CONTROLS) - len(missing) - len(invalid)
    # Invalid booleans never count toward the score.
    score = round(max(satisfied, 0) / len(GOLD_STANDARD_CONTROLS), 4)
    fingerprint = _fingerprint(version, agent_code, missing, invalid)
    return TemplateAssessment(
        template_version=version,
        agent_code=agent_code,
        compliant=not missing and not invalid,
        score=score,
        missing_controls=missing,
        invalid_controls=invalid,
        fingerprint=fingerprint,
    )


def require_compliant_template(manifest: Mapping[str, Any] | dict[str, Any]) -> TemplateAssessment:
    """Assess a manifest and raise when it is noncompliant."""
    return assess_agent_template(manifest).require_compliant()
