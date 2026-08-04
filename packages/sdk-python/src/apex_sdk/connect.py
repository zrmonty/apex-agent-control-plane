"""Apex.connect preflight and local secure first-trace bootstrap."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .bundle import BundleError, load_bundle, local_development_bundle, validate_bundle
from .errors import ConfigurationError
from .observer import BoundedObserver, JsonlSink, ObserverStats
from .reference_runtime import ReferenceReasonActLoop
from .template import (
    AgentTemplateError,
    TemplateAssessment,
    gold_standard_manifest,
    require_compliant_template,
)


class PreflightError(ConfigurationError):
    code = "APEX_PREFLIGHT_FAILED"
    safe_message = "Apex preflight did not reach a ready state."
    cause = "Identity, template, scope, or local profile checks failed before work was allowed to start."
    recommended_next_steps = (
        "Inspect the preflight status and remediation code.",
        "Use a local-development profile for offline demos or regenerate the integration bundle.",
    )


@dataclass(frozen=True)
class PreflightResult:
    status: str  # ready | degraded | blocked
    profile: str
    agent_code: str
    scope: dict[str, str]
    template: TemplateAssessment
    remediation_code: str | None = None
    reasons: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status == "ready"


@dataclass
class Apex:
    """Connected Apex client for a single agent workload."""

    preflight: PreflightResult
    bundle: dict[str, Any]
    _observer: BoundedObserver | None = None
    _trace_path: Path | None = None

    @classmethod
    def connect(
        cls,
        *,
        bundle_path: str | Path | None = None,
        base_dir: str | Path | None = None,
        agent_code: str = "local-agent",
        allow_local_profile: bool = True,
        trace_dir: str | Path | None = None,
        bundle_trust_keys: Mapping[str, str | bytes] | None = None,
        bundle_trust_keys_dir: str | Path | None = None,
        bundle_trust_pins: Mapping[str, str] | None = None,
        require_bundle_signature: bool | None = None,
    ) -> Apex:
        """Discover configuration, assess the gold-standard template, and preflight.

        Local development can run without an ingest endpoint. Production and
        staging bundles require a cryptographically verified, fingerprint-bound
        Ed25519 integration bundle (anti-spoof) before SPIFFE/workload identity
        is used, plus an ingest endpoint reference, and fail closed when template
        controls are noncompliant.

        Trust keys: pass ``bundle_trust_keys`` (key_id → PEM) and/or set
        ``APEX_BUNDLE_TRUST_KEYS_DIR`` to operator-provisioned ``{key_id}.pem``
        files. Prefer ``APEX_BUNDLE_TRUST_PINS`` / ``trust.pins`` so dropped PEMs
        cannot expand the trust set.
        """
        if bundle_path is not None:
            bundle = load_bundle(
                bundle_path,
                base_dir=base_dir,
                trust_public_keys=bundle_trust_keys,
                trust_keys_dir=bundle_trust_keys_dir,
                trust_pins=bundle_trust_pins,
                require_signature=require_bundle_signature,
            )
        elif allow_local_profile:
            bundle = local_development_bundle(agent_code=agent_code)
        else:
            raise PreflightError("bundle_path is required when local profile bootstrap is disabled")

        template_manifest = bundle.get("template") or gold_standard_manifest(bundle["agent_code"])
        try:
            assessment = require_compliant_template(template_manifest)
        except AgentTemplateError as exc:
            raise PreflightError(
                "agent template preflight failed",
                cause=str(exc),
                recommended_next_steps=AgentTemplateError.recommended_next_steps,
            ) from exc

        reasons: list[str] = []
        status = "ready"
        remediation: str | None = None
        profile = bundle["profile"]
        if profile == "local-development" and not bundle.get("ingest_endpoint"):
            status = "degraded" if allow_local_profile else "blocked"
            reasons.append("local-development profile uses offline JSONL telemetry")
            remediation = "LOCAL_OFFLINE_TELEMETRY"
        if profile in {"staging", "production"} and not bundle.get("signature"):
            status = "blocked"
            reasons.append("staging/production require a verified bundle signature before SPIFFE")
            remediation = "BUNDLE_SIGNATURE_REQUIRED"
        if profile in {"staging", "production"} and not bundle.get("ingest_endpoint"):
            status = "blocked"
            reasons.append("staging/production require an ingest endpoint reference")
            remediation = "INGEST_ENDPOINT_REQUIRED"
        if profile == "production" and not bundle.get("trust_bundle_path"):
            status = "blocked"
            reasons.append("production requires a trust bundle reference")
            remediation = "TRUST_BUNDLE_REQUIRED"

        result = PreflightResult(
            status=status,
            profile=profile,
            agent_code=bundle["agent_code"],
            scope=dict(bundle["scope"]),
            template=assessment,
            remediation_code=remediation,
            reasons=tuple(reasons),
        )
        if result.status == "blocked":
            raise PreflightError(
                "preflight blocked agent start",
                cause="; ".join(result.reasons) or PreflightError.cause,
                recommended_next_steps=(
                    f"Remediation code: {result.remediation_code or 'PREFLIGHT_BLOCKED'}",
                    "Correct the integration bundle and retry Apex.connect().",
                ),
            )

        client = cls(preflight=result, bundle=bundle)
        if trace_dir is not None or profile == "local-development":
            client._configure_local_trace(trace_dir or Path(".local") / "apex")
        return client

    def _configure_local_trace(self, output_dir: str | Path) -> None:
        directory = Path(output_dir)
        if directory.exists() and directory.is_symlink():
            raise PreflightError("trace directory must not be a symbolic link")
        directory.mkdir(parents=True, exist_ok=True)
        directory = directory.resolve(strict=True)
        path = directory / "events.jsonl"
        sink = JsonlSink(path, base_dir=directory)
        self._observer = BoundedObserver(sink, capacity=256)
        self._trace_path = path

    @property
    def trace_path(self) -> Path | None:
        return self._trace_path

    def tool_allowed(self, name: str) -> bool:
        allowlist = self.bundle.get("tool_allowlist") or []
        return name in allowlist

    def egress_allowed(self, target: str) -> bool:
        allowlist = self.bundle.get("egress_allowlist") or []
        # Empty egress allowlist means deny-by-default for non-local profiles.
        if self.bundle["profile"] == "local-development" and not allowlist:
            return False
        return target in allowlist

    @contextmanager
    def run(self, run_name: str) -> Iterator[ReferenceReasonActLoop]:
        """Yield a reference reason-act loop after preflight has succeeded."""
        if self.preflight.status == "blocked":
            raise PreflightError("cannot start a run while preflight is blocked")
        if self._observer is None:
            raise PreflightError("no local observer configured; pass trace_dir or use local-development")
        _ = run_name  # reserved for future named-run registration events
        loop = ReferenceReasonActLoop(
            self._observer,
            agent_id=self.preflight.agent_code,
            scope={
                "workspace_id": self.preflight.scope["workspace_id"],
                "namespace_id": self.preflight.scope["namespace_id"],
                "agent_group_ids": [],
            },
            version={
                "agent_code": self.preflight.agent_code,
                "prompt": "connected-run",
                "model": "reference",
            },
        )
        try:
            yield loop
        finally:
            self._observer.close(timeout=2)

    def close(self) -> ObserverStats | None:
        if self._observer is None:
            return None
        self._observer.close(timeout=2)
        return self._observer.stats


def assert_tool_policy(apex: Apex, tool_name: str) -> None:
    if not apex.tool_allowed(tool_name):
        raise PreflightError(
            "tool is not on the approved allowlist",
            cause="Tool execution is deny-by-default outside the bundle allowlist.",
            recommended_next_steps=(
                "Request an updated AgentGroup tool allowlist from an operator.",
                "Do not bypass the allowlist with a local override in production profiles.",
            ),
        )
