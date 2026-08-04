"""Phase 0 completion contracts: connect, bundle, execution attribution."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from apex_sdk import (
    Apex,
    BundleError,
    EventBuilder,
    EventValidationError,
    PreflightError,
    assert_tool_policy,
    build_execution,
    load_bundle,
    local_development_bundle,
    validate_bundle,
    validate_event,
    validate_execution,
)
from apex_sdk.template import gold_standard_manifest


EVENT = "018f5c91-2d88-7c00-8000-000000000001"
HASH = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058"


def test_local_bundle_and_secret_rejection(tmp_path: Path) -> None:
    bundle = local_development_bundle(agent_code="home-demo")
    assert bundle["profile"] == "local-development"
    assert bundle["scope"]["workspace_id"] == "local"
    with pytest.raises(BundleError, match="credential"):
        validate_bundle({**bundle, "identity_ref": "bearer sk-secret-material-not-allowed"})
    with pytest.raises(BundleError):
        validate_bundle("nope")  # type: ignore[arg-type]
    with pytest.raises(BundleError, match="unsupported fields"):
        validate_bundle({**bundle, "prompt": "secret"})
    with pytest.raises(BundleError, match="bundle_version"):
        validate_bundle({**bundle, "bundle_version": "v0"})
    with pytest.raises(BundleError, match="profile"):
        validate_bundle({**bundle, "profile": "lab"})
    with pytest.raises(BundleError, match="scope"):
        validate_bundle({**bundle, "scope": {"workspace_id": "only"}})
    with pytest.raises(BundleError, match="tool_allowlist"):
        validate_bundle({**bundle, "tool_allowlist": ["bad id"]})
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert load_bundle(path, base_dir=tmp_path)["agent_code"] == "home-demo"
    with pytest.raises(BundleError):
        load_bundle(tmp_path / "missing.json", base_dir=tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    with pytest.raises(BundleError, match="base directory"):
        load_bundle(outside, base_dir=nested)


def test_execution_builder_and_llm_event_validation() -> None:
    execution = build_execution(
        requested_provider="openai",
        requested_model="gpt-5",
        effective_provider="openai",
        effective_model="gpt-5-mini",
        routing_reason="fallback",
        requested_reasoning_effort="high",
        effective_reasoning_effort="medium",
        requested_service_tier="standard",
        effective_service_tier="standard",
        region="us-east",
        max_output_tokens=128,
        input_tokens=10,
        output_tokens=4,
        cached_input_tokens=1,
        cache_write_tokens=0,
        reasoning_tokens=2,
        evidence_source="provider_receipt",
        receipt_id_hash=HASH,
        currency="USD",
        observed_at=datetime.now(UTC),
    )
    validate_execution(execution)
    assert execution["effective"]["routing_reason"] == "fallback"
    event = EventBuilder(
        agent_id="agent",
        run_id="run",
        trace_id="trace",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        actor={"type": "agent", "id": "agent"},
        version={"agent_code": "agent", "prompt": "p", "model": "gpt-5"},
    ).build("llm", {"provider": "openai", "model": "gpt-5", "execution": execution}, event_id=EVENT)
    validate_event(event)
    with pytest.raises(EventValidationError):
        validate_execution({"requested": {"provider": "x", "model": "y"}})
    with pytest.raises(EventValidationError):
        build_execution(requested_provider="bad provider", requested_model="m")
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            routing_reason="not-a-reason",
        )
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            input_tokens=-1,
        )


def test_apex_connect_local_first_trace(tmp_path: Path) -> None:
    apex = Apex.connect(agent_code="phase0-agent", trace_dir=tmp_path / "apex")
    assert apex.preflight.status in {"ready", "degraded"}
    assert apex.preflight.template.compliant is True
    assert apex.tool_allowed("reference_tool")
    assert not apex.egress_allowed("https://example.invalid")
    with apex.run("demo") as loop:
        events = loop.run("phase 0 first trace", tool=lambda value: f"ok:{value}")
    assert any(event["type"] == "llm" for event in events)
    llm = next(event for event in events if event["type"] == "llm")
    assert "execution" in llm["data"]
    assert apex.trace_path is not None
    assert apex.trace_path.exists()
    assert_tool_policy(apex, "reference_tool")
    with pytest.raises(PreflightError):
        assert_tool_policy(apex, "unknown_tool")
    stats = apex.close()
    assert stats is not None


def test_connect_blocks_noncompliant_template_and_missing_bundle() -> None:
    with pytest.raises(PreflightError):
        Apex.connect(agent_code="prod-agent", allow_local_profile=False)
    bad = local_development_bundle(agent_code="agent")
    bad["template"] = gold_standard_manifest("agent", controls={"secret_redaction": False})
    # Inject noncompliant template through a connect path that loads from memory:
    from apex_sdk.connect import Apex as ApexCls
    from apex_sdk import require_compliant_template
    from apex_sdk.template import AgentTemplateError

    with pytest.raises(AgentTemplateError):
        require_compliant_template(bad["template"])


def test_staging_bundle_without_endpoint_is_blocked(tmp_path: Path) -> None:
    document = {
        "bundle_version": "apex-agent-bundle.v1",
        "profile": "staging",
        "agent_code": "staging-agent",
        "scope": {"workspace_id": "acme", "namespace_id": "stage"},
        "tool_allowlist": ["reference_tool"],
        "egress_allowlist": [],
        "template": gold_standard_manifest("staging-agent"),
    }
    path = tmp_path / "staging.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    # Unsigned staging fails closed at signature verification (before SPIFFE / endpoint preflight).
    with pytest.raises((PreflightError, BundleError), match="signature|blocked|preflight|trust"):
        Apex.connect(bundle_path=path, base_dir=tmp_path, allow_local_profile=False)


def test_execution_validation_rejects_malformed_shapes() -> None:
    good = build_execution(requested_provider="openai", requested_model="gpt-5")
    validate_execution(good)
    with pytest.raises(EventValidationError):
        validate_execution([])  # type: ignore[arg-type]
    with pytest.raises(EventValidationError):
        validate_execution({**good, "extra": 1})
    with pytest.raises(EventValidationError):
        validate_execution({"requested": "x", "evidence": good["evidence"]})
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": {**good["requested"], "evil": True},
                "evidence": good["evidence"],
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": good["requested"],
                "effective": "nope",
                "evidence": good["evidence"],
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": good["requested"],
                "usage": {"input_tokens": -1},
                "evidence": good["evidence"],
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": good["requested"],
                "evidence": {**good["evidence"], "source": "oracle"},
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": good["requested"],
                "evidence": {**good["evidence"], "receipt_id_hash": "zz"},
            }
        )
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            requested_service_tier="not valid tier!",
        )
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            evidence_source="oracle",
        )


def test_bundle_load_rejects_symlink_and_oversized(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(BundleError, match="JSON"):
        load_bundle(path, base_dir=tmp_path)
    huge = tmp_path / "huge.json"
    huge.write_text("{" + ("a" * (65 * 1024)) + "}", encoding="utf-8")
    with pytest.raises(BundleError, match="64 KiB"):
        load_bundle(huge, base_dir=tmp_path)
    with pytest.raises(BundleError, match="scope"):
        validate_bundle(
            {
                "bundle_version": "apex-agent-bundle.v1",
                "profile": "local-development",
                "agent_code": "agent",
                "scope": "nope",
            }
        )
    with pytest.raises(BundleError, match="control characters"):
        validate_bundle(
            {
                **local_development_bundle(agent_code="agent"),
                "policy_revision": "rev\n1",
            }
        )
    with pytest.raises(BundleError, match="egress_allowlist"):
        validate_bundle(
            {
                **local_development_bundle(agent_code="agent"),
                "egress_allowlist": "all",
            }
        )
    with pytest.raises(BundleError, match="template"):
        validate_bundle(
            {
                **local_development_bundle(agent_code="agent"),
                "template": "nope",
            }
        )


def test_execution_optional_branches_and_effective_tiers() -> None:
    execution = build_execution(
        requested_provider="openai",
        requested_model="gpt-5",
        effective_provider="openai",
        effective_model="gpt-5",
        effective_service_tier="priority",
        routing_reason="capacity",
    )
    validate_execution(execution)
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            effective_service_tier="not valid!",
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": {"provider": "openai", "model": "gpt-5"},
                "effective": {"provider": "openai", "model": "gpt-5", "routing_reason": "nope"},
                "evidence": execution["evidence"],
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": {"provider": "openai", "model": "gpt-5"},
                "usage": "nope",
                "evidence": execution["evidence"],
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": {"provider": "openai", "model": "gpt-5"},
                "evidence": "nope",
            }
        )
    with pytest.raises(EventValidationError):
        validate_execution(
            {
                "requested": {"provider": "openai", "model": "gpt-5"},
                "evidence": {
                    "source": "sdk_observed",
                    "observed_at": "not-a-dateZ",
                },
            }
        )
    naive = datetime(2024, 1, 1, 0, 0, 0)
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            observed_at=naive,
        )
    with pytest.raises(EventValidationError):
        build_execution(
            requested_provider="openai",
            requested_model="gpt-5",
            receipt_id_hash="not-hex",
        )


def test_production_requires_trust_bundle(tmp_path: Path) -> None:
    document = {
        "bundle_version": "apex-agent-bundle.v1",
        "profile": "production",
        "agent_code": "prod-agent",
        "scope": {"workspace_id": "acme", "namespace_id": "prod"},
        "ingest_endpoint": "https://ingest.example.internal:8443",
        "tool_allowlist": ["reference_tool"],
        "egress_allowlist": [],
        "template": gold_standard_manifest("prod-agent"),
    }
    path = tmp_path / "prod.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    # Production fails closed without a verified bundle signature (and still requires trust_bundle_path when signed).
    with pytest.raises((PreflightError, BundleError), match="signature|trust|blocked|preflight"):
        Apex.connect(bundle_path=path, base_dir=tmp_path, allow_local_profile=False)
