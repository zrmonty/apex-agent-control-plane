"""Deterministic gold-standard agent-template compliance assessment."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .errors import ConfigurationError

TEMPLATE_VERSION = "apex-agent-template.v1"
SAFE_NAME = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

# These are implementation controls that support, but do not themselves certify,
# SOC 2, HIPAA, SEC, and FedRAMP readiness.
GOLD_STANDARD_CONTROLS = (
    "scope_bound_identity",
    "short_lived_credentials",
    "validated_hash_chain",
    "bounded_event_capture",
    "lifecycle_events",
    "secret_redaction",
    "untrusted_content_taint_boundary",
    "tool_allowlist",
    "egress_denied_by_default",
    "stable_redacted_diagnostics",
)
HIGH_IMPACT_CONTROLS = frozenset(
    {
        "scope_bound_identity",
        "short_lived_credentials",
        "secret_redaction",
        "untrusted_content_taint_boundary",
        "tool_allowlist",
        "egress_denied_by_default",
    }
)

# Evidence-oriented mappings only. Presence of a control does not establish
# certification or satisfy an organization's complete control framework.
CONTROL_FRAMEWORK_MAP = {
    "scope_bound_identity": ("SOC2-CC6", "HIPAA-164.312(d)", "FedRAMP-AC-2"),
    "short_lived_credentials": ("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-IA-5"),
    "validated_hash_chain": ("SOC2-CC7", "SEC-17a-4", "FedRAMP-AU-10"),
    "bounded_event_capture": ("SOC2-CC7", "HIPAA-164.312(b)", "FedRAMP-AU-2"),
    "lifecycle_events": ("SOC2-CC7", "HIPAA-164.308(a)(1)", "FedRAMP-AU-2"),
    "secret_redaction": ("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-SC-28"),
    "untrusted_content_taint_boundary": ("SOC2-CC6", "HIPAA-164.308(a)(5)", "FedRAMP-SI-10"),
    "tool_allowlist": ("SOC2-CC6", "HIPAA-164.312(a)", "FedRAMP-AC-3"),
    "egress_denied_by_default": ("SOC2-CC6", "HIPAA-164.312(e)", "FedRAMP-SC-7"),
    "stable_redacted_diagnostics": ("SOC2-CC7", "HIPAA-164.312(b)", "FedRAMP-AU-3"),
}


class AgentTemplateError(ConfigurationError):
    code = "AGENT_TEMPLATE_INVALID"
    safe_message = "The agent template manifest is not valid."
    cause = "The template manifest must contain bounded, non-secret capability declarations."
    recommended_next_steps = (
        "Provide the required Apex template version and boolean control declarations.",
        "Do not include prompts, completions, credentials, or raw tool output in the manifest.",
    )


@dataclass(frozen=True)
class TemplateAssessment:
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
        return "high" if len(self.missing_controls) >= 3 or self.invalid_controls or high_impact_gap else "medium"

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
            "recommended_action": "quarantine_or_require_review",
        }

    def event_data(self) -> dict[str, Any]:
        """Return bounded metadata suitable for a `score` or `error` event."""
        return {
            "assessment": "agent_template",
            "template_version": self.template_version,
            "agent_code": self.agent_code,
            "compliant": self.compliant,
            "score_basis": "gold_standard_control_count",
            "score": self.score,
            "missing_control_count": len(self.missing_controls),
            "invalid_control_count": len(self.invalid_controls),
            "missing_controls": list(self.missing_controls),
            "invalid_controls": list(self.invalid_controls),
            "fingerprint": self.fingerprint,
        }


def assess_agent_template(manifest: dict[str, Any]) -> TemplateAssessment:
    """Assess a non-secret capability manifest against the gold standard."""
    if not isinstance(manifest, dict):
        raise AgentTemplateError("agent template must be an object")
    allowed = {"template_version", "agent_code", "controls"}
    unknown = set(manifest) - allowed
    if unknown:
        raise AgentTemplateError("agent template contains unsupported fields")
    version = manifest.get("template_version")
    agent_code = manifest.get("agent_code")
    controls = manifest.get("controls")
    if version != TEMPLATE_VERSION or not isinstance(agent_code, str) or not SAFE_NAME.fullmatch(agent_code) or not isinstance(controls, dict):
        raise AgentTemplateError("agent template requires a valid version, agent_code, and controls object")
    if len(controls) > len(GOLD_STANDARD_CONTROLS):
        raise AgentTemplateError("agent template controls exceed the supported bounded set")
    unknown_controls = set(controls) - set(GOLD_STANDARD_CONTROLS)
    if unknown_controls:
        raise AgentTemplateError("agent template contains unsupported controls")
    invalid = tuple(sorted(name for name, value in controls.items() if not isinstance(value, bool)))
    missing = tuple(name for name in GOLD_STANDARD_CONTROLS if controls.get(name) is not True)
    satisfied = len(GOLD_STANDARD_CONTROLS) - len(missing)
    score = round(satisfied / len(GOLD_STANDARD_CONTROLS), 4)
    fingerprint = hashlib.sha256(
        (f"{version}:{agent_code}:{','.join(missing)}:{','.join(invalid)}").encode("ascii")
    ).hexdigest()
    return TemplateAssessment(version, agent_code, not missing and not invalid, score, missing, invalid, fingerprint)
